function register ({ registerHook, registerSettingsScript, registerClientRoute, peertubeHelpers }) {
    registerHook({
        target: 'action:application.init',
        handler: () => onApplicationInit(peertubeHelpers)
    })
    
    registerHook({
      target: 'action:login.init',
      handler: () => {
        const params = new URL(location.href).searchParams;
        const previousUrl = document.referrer.trim(); 
        const BASE_URL = '/plugins/oidc-cnr/0.0.5/auth/openid-connect';
        if (!params.get('username')) {
          location.href = BASE_URL + (previousUrl ? '?previousUrl=' + previousUrl : ''); 
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