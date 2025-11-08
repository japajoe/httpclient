#include "../../httpclient/include/client.hpp"
#include <iostream>

int main(int argc, char **argv)
{
	http::client client(false);

	std::string responseText;

	client.onResponse = [&] (const void *data, size_t size) {
		if(data && size > 0)
			responseText += std::string((char*)data, size);
	};

	http::request request;
	request.set_url("https://api.ipify.org");
	request.set_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/123.0");
	
	http::response response;

	if(client.get(request, response))
	{
		std::cout << "Status: " << response.get_status_code() << '\n';

		auto headers = response.get_headers();

		for(const auto &h : headers)
		{
			std::cout << h.first << ": " << h.second << '\n';
		}

		if(responseText.size() > 0)
			std::cout << responseText << '\n';
	}
	else
		std::cout << "Failed to make request\n";

	return 0;
}