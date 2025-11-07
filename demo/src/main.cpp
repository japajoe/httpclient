#include "../../httpclient/include/client.hpp"
#include <iostream>

int main(int argc, char **argv)
{
	http::client client;

	http::request request;
	request.set_url("https://www.whatismyip.com");
	request.set_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/123.0");
	
	http::response response;

	if(client.get(request, response))
		std::cout << "Status: " << response.get_status_code()<< "\n" << response.get_content_as_string() << '\n';
	else
		std::cout << "Failed to make request\n";

	return 0;
}