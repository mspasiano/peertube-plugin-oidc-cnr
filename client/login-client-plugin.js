function register ({ registerHook, registerSettingsScript, registerClientRoute, peertubeHelpers }) {
  registerHook({
      target: 'action:application.init',
      handler: () => onApplicationInit(peertubeHelpers)
  })
  
  registerHook({
    target: 'action:login.init',
    handler: () => {
      const params = new URL(location.href).searchParams;
      if (!params.get('username')) {
        document.querySelector('a.external-login-block').click(); 
      }
    }
  })

  registerHook({
    target: 'action:auth-user.logged-in',
    handler: () => {
      const previousUrl = decodeURIComponent(getCookieValue('plugin-auth-openid-code-verifier-previousUrl'));
      if (previousUrl)
        location.href = previousUrl;
    }
  })
}

export {
  register
}

function getCookieValue (name) {
  return document.cookie.match('(^|;)\\s*' + name + '\\s*=\\s*([^;]+)')?.pop() || '';
};