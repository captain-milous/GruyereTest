# GruyereTest

## Autor: Miloš Tesař C4b

## Změny v kódu

### Zde jsem využil funkci cgi.escape() k zabezpečení vstupních dat od uživatele. Tímto způsobem se snižuje riziko útoků typu XSS tím, že se zakáží interpretace HTML tagů a JavaScriptu ve vstupních datech.

Tato metoda transformuje speciální znaky HTML na jejich entitní reprezentace, čímž se brání možnosti interpretace HTML tagů a JavaScriptu.

```
def _GetParameter(self, params, name, default=None):
    if params.get(name):
        # Zde se provádí sanitizace inputu pomocí cgi.escape()
        return cgi.escape(params[name][0])
    return default

def _GetCookie(self, cookie_name):
    cookies = self.headers.get('Cookie')
    if isinstance(cookies, str):
        for c in cookies.split(';'):
            matched_cookie = self._MatchCookie(cookie_name, c)
            if matched_cookie:
                return self._ParseCookie(matched_cookie)
    return self.NULL_COOKIE
```

### Tímto je zajištěno, že každý požadavek na odstranění úryvku obsahuje platný CSRF token, který musí odpovídat očekávané hodnotě, což brání úspěšnému XSRF útoku.

```
def _GenerateCSRFToken(self):
    return secrets.token_hex(16)  # Generuje náhodný CSRF token

def _GetCSRFToken(self):
    cookie = self._GetCookie('GRUYERE')
    csrf_token = cookie.get('csrf_token')
    if not csrf_token:
        csrf_token = self._GenerateCSRFToken()
        cookie['csrf_token'] = csrf_token
        # Zde by mělo být uložení CSRF tokenu do cookie pro následné použití
    return csrf_token

def _CheckCSRFToken(self, token):
    # Ověření CSRF tokenu
    # Porovnání s uloženým tokenem ve formuláři nebo v session
    expected_token = self._GetCSRFToken()
    return token == expected_token

def _DoDeletesnippet(self, cookie, specials, params):
    if not self._CheckCSRFToken(params.get('csrf_token')):
        self._SendError('Invalid CSRF token.', cookie, specials, params)
        return
            
    index = self._GetParameter(params, 'index')
    snippets = self._GetSnippets(cookie, specials)
    try:
      del snippets[int(index)]
    except (IndexError, TypeError, ValueError):
      self._SendError(
          'Invalid index (%s)' % (index,),
          cookie, specials, params)
      return
    self._SendRedirect('/snippets.gtl', specials[SPECIAL_UNIQUE_ID])
    
```

### Další části, kde by se ochrana XSRF hodila:

* Vytváření nových snippetů (_DoNewsnippet2 funkce)
* Nahrazení existujících snippetů (_DoUpload2 funkce)
* Úprava profilu uživatele (_DoSaveprofile funkce)
* Resetování databáze (_DoReset funkce)


## Závěr

Hlavním cílem je zajistit integritu a bezpečnost aplikace, a tím chránit jak uživatele, tak data samotné aplikace.