#ifndef _OAUTH2_H_
#define _OAUTH2_H_

#include <map>
#include <string>

namespace oauth2 {

class OAuth2 {
private:
	std::string m_clientId;
    std::string m_clientSecret;
    std::string m_redirectUri;
    std::string m_authorizationCode;
    std::string m_curlData;

public:
	enum scope {
		CHARACTER_ALL,
		UNKNOWN
	};

	std::map<scope, std::string> const m_scopeLiterals = {{CHARACTER_ALL, "character_all"}};

	OAuth2(std::string const& clientId, std::string const& clientSecret);

	std::string generateAuthorizationURL(std::string const& endpoint, scope const& requestedScope) const;
	void setAuthorizationCode(std::string const& code) {m_authorizationCode = code;}
	std::pair<std::string const&, std::string const&> getTokens(void) const;
	void getResource(std::string const& endpoint) const;
	//void getAuthorizationCode();
	//void getAccessToken();
	//void refreshAccessToken();

	static size_t writeTokens(void *buffer, size_t size, size_t nmemb, void *userp);
};

}

#endif // _OAUTH2_H_
