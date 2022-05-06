const openidModule = require('openid-client')
const crypto = require('crypto')

const store = {
  client: null,
  userAuthenticated: null,
  secretKey: null,
  redirectUrl: null,
  authDisplayName: 'OpenID Connect'
}

const encryptionOptions = {
  algorithm: 'aes256',
  inputEncoding: 'utf8',
  outputEncoding: 'hex'
}

const cookieNamePrefix = 'plugin-auth-openid-code-verifier-'

async function register ({
  registerExternalAuth,
  unregisterExternalAuth,
  registerSetting,
  settingsManager,
  peertubeHelpers,
  getRouter
}) {
  const { logger } = peertubeHelpers

  registerSetting({
    name: 'auth-display-name',
    label: 'Auth display name',
    type: 'input',
    private: true,
    default: 'OpenID Connect'
  })

  registerSetting({
    name: 'discover-url',
    label: 'Discover URL',
    type: 'input',
    private: true
  })

  registerSetting({
    name: 'client-id',
    label: 'Client ID',
    type: 'input',
    private: true
  })

  registerSetting({
    name: 'client-secret',
    label: 'Client secret',
    type: 'input',
    private: true
  })

  registerSetting({
    name: 'scope',
    label: 'Scope',
    type: 'input',
    private: true,
    default: 'openid email profile'
  })

  registerSetting({
    name: 'username-property',
    label: 'Username property',
    type: 'input',
    private: true,
    default: 'preferred_username'
  })

  registerSetting({
    name: 'mail-property',
    label: 'Email property',
    type: 'input',
    private: true,
    default: 'email'
  })

  registerSetting({
    name: 'display-name-property',
    label: 'Display name property',
    type: 'input',
    private: true
  })

  registerSetting({
    name: 'role-property',
    label: 'Role property',
    type: 'input',
    private: true
  })

  registerSetting({
    name: 'group-property',
    label: 'Group property',
    type: 'input',
    private: true,
    descriptionHTML: 'Property/claim that contains user groups (array)'
  })

  registerSetting({
    name: 'allowed-group',
    label: 'Allowed group',
    type: 'input',
    private: true,
    descriptionHTML: 'Will only allow login for users whose group array contains this group'
  })

  registerSetting({
    name: 'access-property',
    label: 'Access property',
    type: 'input',
    private: true,
    descriptionHTML: 'Boolean Property for discriminate access'
  })

  registerSetting({
    name: 'signature-algorithm',
    label: 'Token signature algorithm',
    type: 'input',
    private: true,
    default: 'RS256'
  })

  const router = getRouter()
  router.use('/code-cb', (req, res) => handleCb(peertubeHelpers, settingsManager, req, res))

  store.redirectUrl = peertubeHelpers.config.getWebserverUrl() + '/plugins/oidc-cnr/router/code-cb'

  const secretKeyBuf = await getRandomBytes(16)
  store.secretKey = secretKeyBuf.toString('hex')

  settingsManager.onSettingsChange(settings => {
    loadSettingsAndCreateClient(registerExternalAuth, unregisterExternalAuth, peertubeHelpers, settingsManager)
      .catch(err => logger.error('Cannot load settings and create client after settings changes.', { err }))

    if (settings['auth-display-name']) store.authDisplayName = settings['auth-display-name']
  })

  try {
    await loadSettingsAndCreateClient(registerExternalAuth, unregisterExternalAuth, peertubeHelpers, settingsManager)
  } catch (err) {
    logger.error('Cannot load settings and create open id client.', { err })
  }

  store.authDisplayName = await settingsManager.getSetting('auth-display-name')
}

async function unregister () {
  return
}

module.exports = {
  register,
  unregister
}

// ############################################################################

async function loadSettingsAndCreateClient (registerExternalAuth, unregisterExternalAuth, peertubeHelpers, settingsManager) {
  const { logger } = peertubeHelpers

  if (store.client) {
    unregisterExternalAuth('openid-connect')
  }

  store.client = null
  store.userAuthenticated = null

  const settings = await settingsManager.getSettings([
    'scope',
    'discover-url',
    'client-id',
    'client-secret',
    'signature-algorithm'
  ])

  if (!settings['discover-url']) {
    logger.info('Do not register external openid auth because discover URL is not set.')
    return
  }

  if (!settings['client-id']) {
    logger.info('Do not register external openid auth because client ID is not set.')
    return
  }

  const discoverUrl = settings['discover-url']
  const issuer = await openidModule.Issuer.discover(discoverUrl)

  logger.debug('Discovered issuer %s.', discoverUrl)

  const clientOptions = {
    client_id: settings['client-id'],
    redirect_uris: [ store.redirectUrl ],
    response_types: [ 'code' ],
    id_token_signed_response_alg: settings['signature-algorithm'],
    authorization_signed_response_alg: settings['signature-algorithm']
  }

  if (settings['client-secret']) {
    clientOptions.client_secret = settings['client-secret']
  } else {
    clientOptions.token_endpoint_auth_method = 'none'
  }

  store.client = new issuer.Client(clientOptions)

  const result = registerExternalAuth({
    authName: 'openid-connect',
    authDisplayName: () => store.authDisplayName,
    onAuthRequest: async (req, res) => {
      try {
        const codeVerifier = openidModule.generators.codeVerifier()
        const codeChallenge = openidModule.generators.codeChallenge(codeVerifier)
        const state = openidModule.generators.state()

        const redirectUrl = store.client.authorizationUrl({
          scope: settings['scope'],
          response_mode: 'form_post',
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
          state,
        })

        const cookieOptions = {
          secure: true,
          httpOnly: false,
          sameSite: 'none',
          maxAge: 1000 * 60 * 10 // 10 minutes
        }

        const encryptedCodeVerifier = await encrypt(codeVerifier)
        res.cookie(cookieNamePrefix + 'code-verifier', encryptedCodeVerifier, cookieOptions)

        const encryptedState = await encrypt(state)
        res.cookie(cookieNamePrefix + 'state', encryptedState, cookieOptions)

        if (req.query.previousUrl) {
          res.cookie(cookieNamePrefix + 'previousUrl', req.query.previousUrl, cookieOptions)          
        }

        return res.redirect(redirectUrl)
      } catch (err) {
        logger.error('Cannot handle auth request.', { err })
      }
    }
  })

  store.userAuthenticated = result.userAuthenticated
}

async function handleCb (peertubeHelpers, settingsManager, req, res) {
  const { logger } = peertubeHelpers

  if (!store.userAuthenticated) {
    logger.info('Received callback but cannot userAuthenticated function does not exist.')
    return onCBError(res)
  }

  const encryptedCodeVerifier = req.cookies[cookieNamePrefix + 'code-verifier']
  if (!encryptedCodeVerifier) {
    logger.error('Received callback but code verifier not found in request cookies.')
    return onCBError(res)
  }

  const encryptedState = req.cookies[cookieNamePrefix + 'state']
  if (!encryptedState) {
    logger.error('Received callback but state not found in request cookies.')
    return onCBError(res)
  }


  try {
    const codeVerifier = await decrypt(encryptedCodeVerifier)
    const state = await decrypt(encryptedState)

    const params = store.client.callbackParams(req)
    const tokenSet = await store.client.callback(store.redirectUrl, params, {
      code_verifier: codeVerifier,
      state,
    })

    const accessToken = tokenSet.access_token
    const userInfo = await store.client.userinfo(accessToken)

    const settings = await settingsManager.getSettings([
      'mail-property',
      'username-property',
      'display-name-property',
      'role-property',
      'group-property',
      'allowed-group',
      'access-property'
    ])

    logger.debug('Got userinfo from openid auth.', { userInfo, settings })

    let role
    if (settings['role-property']) {
      let roleToParse = userInfo[settings['role-property']];
      if (roleToParse.tube && roleToParse.tube.roles.indexOf('Administrator#tube') !== -1) {
        role = 0;
      } else if (roleToParse.tube && roleToParse.tube.roles.indexOf('Moderator#tube') !== -1) {
        role = 1;
      } else {
        role = 2;
      }
    }

    if (settings['group-property'] && settings['allowed-group']) {
      const groups = userInfo[settings['group-property']]

      if (!groups.includes(settings['allowed-group'])) {
        throw {
          name: "AllowedGroupNotFound",
          message: "User is not in allowed group"
        }
      }
    }

    if (settings['access-property']) {
      const access = userInfo[settings['access-property']]
      if (!access) {
        throw {
          name: "AllowedGroupNotFound",
          message: "User is not in allowed group"
        }
      }
    }

    let displayName
    if (settings['display-name-property']) {
      displayName = userInfo[settings['display-name-property']]
    }

    let username = userInfo[settings['username-property']] || ''
    username = username.replace(/[^a-z0-9._]/g, '_')

    store.userAuthenticated({
      res,
      req,
      username,
      email: userInfo[settings['mail-property']],
      displayName,
      role
    })

  } catch (err) {
    logger.error('Error in handle callback.', { err })
    onCBError(res)
  }
}

function onCBError (res) {
  res.redirect('/login?externalAuthError=true')
}

async function encrypt (data) {
  const { algorithm, inputEncoding, outputEncoding } = encryptionOptions

  const iv = await getRandomBytes(16)

  const cipher = crypto.createCipheriv(algorithm, store.secretKey, iv)
  let encrypted = cipher.update(data, inputEncoding, outputEncoding)
  encrypted += cipher.final(outputEncoding)

  return iv.toString(outputEncoding) + ':' + encrypted
}

async function decrypt (data) {
  const { algorithm, inputEncoding, outputEncoding } = encryptionOptions

  const encryptedArray = data.split(':')
  const iv = Buffer.from(encryptedArray[0], outputEncoding)
  const encrypted = Buffer.from(encryptedArray[1], outputEncoding)
  const decipher = crypto.createDecipheriv(algorithm, store.secretKey, iv)

  return decipher.update(encrypted, outputEncoding, inputEncoding) + decipher.final(inputEncoding)
}

function getRandomBytes (size) {
  return new Promise((res, rej) => {
    crypto.randomBytes(size, (err, buf) => {
      if (err) return rej(err)

      return res(buf)
    })
  })
}
