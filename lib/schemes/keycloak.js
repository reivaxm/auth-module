import defu from 'defu'
import { getProp } from '../utilities'
import RequestHandler from '../requestHandler'

export default class KeycloakScheme {
  constructor (auth, options) {
    this.$auth = auth
    this.name = options._name

    this.options = defu(options, DEFAULTS)

    // Initialize Request Interceptor
    this.requestHandler = new RequestHandler(this.$auth)
  }

  mounted () {
    // Sync token
    this.$auth.token.sync()
    this.$auth.refreshToken.sync()

    // Get token status
    const tokenStatus = this.$auth.token.status()

    // Token is expired. Force reset.
    if (tokenStatus.expired()) {
      this.$auth.reset()
    }

    // Initialize request interceptor
    this.requestHandler.initializeRequestInterceptor()

    // Fetch user once
    return this.$auth.fetchUserOnce()
  }

  async login (payload = {}) {
    if (!this.options.keycloak.host || !this.options.keycloak.realm || !this.options.keycloak.clientId) {
      return
    }

    // Ditch any leftover local tokens before attempting to log in
    await this.$auth.reset()

    // QueryParm builder
    const queryParams = new URLSearchParams()
    queryParams.append('client_id', this.options.keycloak.clientId)
    queryParams.append('grant_type', 'password')
    for (const [key, value] of Object.entries(payload)) {
      queryParams.append(key, value)
    }

    // Make login request
    const { response, data } = await this.$auth.request({}, {
      url: this.options.keycloak.host + '/auth/realms/' + this.options.keycloak.realm + '/protocol/openid-connect/token',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json'
      },
      data: queryParams
    })

    // Update Token
    this.$auth.token.set(getProp(data, this.options.token.property))

    // Store refresh token
    if (data[this.options.refreshToken.property]) {
      this.$auth.refreshToken.set(getProp(data, this.options.refreshToken.property))
    }

    // Fetch user
    if (this.options.user.autoFetch) {
      await this.fetchUser()
    }

    return response
  }

  async setUserToken (tokenValue) {
    this.$auth.token.set(getProp(tokenValue, this.options.token.property))

    // Fetch user
    return this.fetchUser()
  }

  async fetchUser (endpoint) {
    // Try to fetch user and then set
    const { data } = await this.$auth.requestWith(
      this.name,
      endpoint,
      {
        url: this.options.keycloak.host + '/auth/realms/' + this.options.keycloak.realm + '/protocol/openid-connect/userinfo',
        headers: {
          Accept: 'application/json'
        }
      }
    )

    this.$auth.setUser(data)
  }

  async logout (endpoint = {}) {
    // QueryParm builder
    const queryParams = new URLSearchParams()
    queryParams.append('refresh_token', this.$auth.refreshToken.get())
    queryParams.append('client_id', this.options.keycloak.clientId)

    await this.$auth
      .requestWith(
        this.name,
        {
          url: this.options.keycloak.host + '/auth/realms/' + this.options.keycloak.realm + '/protocol/openid-connect/logout',
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Accept: 'application/json'
          },
          data: queryParams
        },
        {}
      )
      .catch(() => { })

    // But reset regardless
    return this.$auth.reset()
  }

  async reset () {
    this.$auth.setUser(false)
    this.$auth.token.reset()
    this.$auth.refreshToken.reset()

    return Promise.resolve()
  }
}

const DEFAULTS = {
  keycloak: {
    host: 'https://localhost:8443',
    realm: 'Realm',
    clientId: 'AppName'
  },
  token: {
    property: 'access_token',
    type: 'Bearer',
    name: 'Authorization',
    maxAge: 1800,
    global: true
  },
  refreshToken: {
    property: 'refresh_token',
    maxAge: 60 * 60 * 24 * 30
  },
  user: {
    property: 'user',
    autoFetch: true
  }
}
