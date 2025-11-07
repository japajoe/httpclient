#include "../../httpclient/include/client.hpp"
#include <iostream>

int main(int argc, char **argv)
{
	http::client client;

	http::request request;
	request.set_url("http://api.ipify.org");
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

		if(response.get_content_length() > 0)
			std::cout << response.get_content_as_string() << '\n';
	}
	else
		std::cout << "Failed to make request\n";

	return 0;
}