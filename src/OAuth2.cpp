#include "include/OAuth2.h"

#include <curl/curl.h>
#include <iostream>
#include <picojson.h>

using namespace oauth2;

size_t OAuth2::writeTokens(void *buffer, size_t size, size_t nmemb, void *userp) {
	const char* json = reinterpret_cast<char *>(buffer);
    std::string err;
    picojson::value content;

    picojson::parse(content, json, json + strlen(json), &err);
    if (!err.empty()) {
        std::cerr << err << std::endl;
    } else {
        if (content.is<picojson::object>()) {
            std::cout << "input is an object" << std::endl;
            const picojson::object& o = content.get<picojson::object>();
            for (picojson::object::const_iterator i = o.begin(); i != o.end(); ++i) {
                std::cout << i->first << "  " << i->second << std::endl;
            }
        } else {
            std::cerr << "Should be an object..." << std::endl;
        }
    }

	return size * nmemb;
}

OAuth2::OAuth2(std::string const& clientId, std::string const& clientSecret) : m_clientId(clientId), m_clientSecret(clientSecret), m_redirectUri("urn:ietf:wg:oauth:2.0:oob"), m_authorizationCode(""), m_curlData("") {
}

std::string OAuth2::generateAuthorizationURL(std::string const& endpoint, scope const& requestedScope) const {
	std::string fullURL(endpoint);

	fullURL += "?client_id=" + m_clientId;
	fullURL += "&response_type=code";
	fullURL += "&redirect_uri=" + m_redirectUri;
	fullURL += "&scope=" + m_scopeLiterals.at(requestedScope);
	fullURL += "&access_type=offline";

	return fullURL;
}

std::pair<std::string const&, std::string const&> OAuth2::getTokens(void) const {
	curl_global_init(CURL_GLOBAL_ALL);

	CURL *curl(curl_easy_init());
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, "http://www.swcombine.com/ws/oauth2/token/");
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeTokens);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &m_curlData);

		struct curl_slist *headers = NULL;
		headers = curl_slist_append(headers, "Expect:");
		headers = curl_slist_append(headers, "Accept: application/json");
		headers = curl_slist_append(headers, "Transfer-Encoding: chunked");
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		std::string postFields("code=");
		postFields += m_authorizationCode;
		postFields += "&client_id=";
		postFields += m_clientId;
		postFields += "&client_secret=";
		postFields += m_clientSecret;
		postFields += "&redirect_uri=";
		postFields += m_redirectUri;
		postFields += "&grant_type=authorization_code";
		postFields += "&access_type=offline";

		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postFields.c_str());

		CURLcode result(curl_easy_perform(curl));
		if (CURLE_OK != result) {
			std::cerr << "curl call failed: " << curl_easy_strerror(result) << std::endl;
		}

		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);
	}

	curl_global_cleanup();
	return {"", ""};
}

void OAuth2::getResource(std::string const& endpoint) const {
}
