#include "../../httpclient/include/client.hpp"
#include <iostream>

int main(int argc, char **argv)
{
	http::client client;

	std::string request = "https://www.whatismyip.com";
	std::string response;
	int statusCode;

	http::headers headers = {
		{ "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/123.0" }
	};

	if(client.get(request, &headers, statusCode, response))
		std::cout << "Status: " << statusCode << "\n" << response << '\n';
	else
		std::cout << "Failed to make request\n";

	return 0;
}