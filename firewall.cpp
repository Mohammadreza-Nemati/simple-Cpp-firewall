#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <mutex>          
#include <unordered_map>
#include <winsock2.h>
#include <psapi.h>
#include <shlwapi.h>

#include <algorithm>
#include <cctype>
#include <locale>

#include <conio.h>

#include <ctime>

#include <windows.h>
#include <stdio.h>
#include <netfw.h>

#include "windivert.h"

#pragma comment( lib, "ole32.lib" )

using namespace std;

// Convert 16-bit number from network byte order to host byte order
#define ntohs(x)            WinDivertHelperNtohs(x)

// Convert 32-bit number from network byte order to host byte order
#define ntohl(x)            WinDivertHelperNtohl(x)

// Convert 16-bit number from host byte order to network byte order
#define htons(x)            WinDivertHelperHtons(x)

// Convert 32-bit number from host byte order to network byte order
#define htonl(x)            WinDivertHelperHtonl(x)




// Function to initialize the Windows Firewall COM object
// This function creates an instance of the INetFwPolicy2 interface to interact with the Windows Firewall
HRESULT WFCOMInitialize(INetFwPolicy2** ppNetFwPolicy2)
{
	// Initialize HRESULT variable to S_OK (success)
	HRESULT hr = S_OK;

	// Call CoCreateInstance to create an instance of the Windows Firewall COM object
	hr = CoCreateInstance(
		__uuidof(NetFwPolicy2),  // CLSID of the COM object to be created
		NULL,                    // No aggregation, set to NULL
		CLSCTX_INPROC_SERVER,    // Context to run the code in (in-process server)
		__uuidof(INetFwPolicy2), // IID of the interface we want to access
		(void**)ppNetFwPolicy2   // Pointer to the interface pointer to receive the object
	);

	// Check if the CoCreateInstance call failed
	if (FAILED(hr))
	{
		// If CoCreateInstance failed, goto the Cleanup section
		goto Cleanup;
	}

Cleanup:
	// Return the HRESULT value, indicating success or failure
	return hr;
}


// Declare three VARIANT_BOOL variables to store the firewall status for different network profiles
VARIANT_BOOL fw_domain, fw_private, fw_public;

// Function to enable or disable the Windows Firewall
// Parameters:
// - enable: If true, the firewall will be enabled. If false, the firewall will be disabled.
int winfw(bool enable)
{
	// Initialize HRESULT variables for COM initialization and operation results
	HRESULT hrComInit = S_OK;
	HRESULT hr = S_OK;

	// Pointer to the INetFwPolicy2 interface used to manage the firewall
	INetFwPolicy2* pNetFwPolicy2 = NULL;

	// Initialize the COM library for use by the calling thread
	hrComInit = CoInitializeEx(0, COINIT_APARTMENTTHREADED);

	// Check if the COM library was initialized successfully or if it was already initialized
	if (hrComInit != RPC_E_CHANGED_MODE)
	{
		if (FAILED(hrComInit))
		{
			// If COM initialization failed, exit to the Cleanup section
			goto Cleanup;
		}
	}

	// Initialize the firewall policy interface
	hr = WFCOMInitialize(&pNetFwPolicy2);
	if (FAILED(hr))
	{
		// If initializing the firewall interface failed, exit to the Cleanup section
		goto Cleanup;
	}

	if (enable)
	{
		// Enable the firewall for all network profiles
		hr = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_DOMAIN, VARIANT_TRUE);
		if (FAILED(hr)) goto Cleanup;

		hr = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_PRIVATE, VARIANT_TRUE);
		if (FAILED(hr)) goto Cleanup;

		hr = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_PUBLIC, VARIANT_TRUE);
		if (FAILED(hr)) goto Cleanup;
	}
	else
	{
		// Disable the firewall for all network profiles
		hr = pNetFwPolicy2->get_FirewallEnabled(NET_FW_PROFILE2_DOMAIN, &fw_domain);
		if (FAILED(hr)) goto Cleanup;

		hr = pNetFwPolicy2->get_FirewallEnabled(NET_FW_PROFILE2_PRIVATE, &fw_private);
		if (FAILED(hr)) goto Cleanup;

		hr = pNetFwPolicy2->get_FirewallEnabled(NET_FW_PROFILE2_PUBLIC, &fw_public);
		if (FAILED(hr)) goto Cleanup;

		hr = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_DOMAIN, VARIANT_FALSE);
		if (FAILED(hr)) goto Cleanup;

		hr = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_PRIVATE, VARIANT_FALSE);
		if (FAILED(hr)) goto Cleanup;

		hr = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_PUBLIC, VARIANT_FALSE);
		if (FAILED(hr)) goto Cleanup;
	}

Cleanup:

	// Release the INetFwPolicy2 interface pointer if it is not null
	if (pNetFwPolicy2 != NULL)
	{
		pNetFwPolicy2->Release();
	}

	// Uninitialize the COM library if it was initialized successfully
	if (SUCCEEDED(hrComInit))
	{
		CoUninitialize();
	}

	// Return 0 indicating the function execution is complete
	// A more robust implementation might return different values based on the success or failure of operations
	return 0;
}


// Function to split a string into arguments based on spaces
// Ignores anything after a '#' character (comments)
std::vector<std::string> split_args(std::string str)
{
	// Vector to store the resulting arguments
	std::vector<std::string> tmp;
	// Temporary string to accumulate characters of the current argument
	std::string arg = "";

	// Iterate through each character in the input string
	for (std::string::size_type i = 0; i < str.size(); i++)
	{
		// Get the current character
		char c = str[i];

		// If the current character is a '#', stop processing
		if (c == '#')
		{
			break;
		}
		// If the current character is a whitespace
		else if (isspace(c))
		{
			// If arg is not empty, add it to the vector
			if (!arg.empty())
			{
				tmp.push_back(arg);
				// Reset arg for the next word
				arg = "";
			}
		}
		// If the current character is part of an argument
		else
		{
			arg.push_back(c);
		}
	}

	// Add the last argument if it's not empty
	if (!arg.empty())
	{
		tmp.push_back(arg);
	}

	// Return the vector of arguments
	return tmp;
}




// Function to split a string into substrings based on a delimiter
// Parameters:
// - str: The input string to split
// - del: The delimiter character to split the string
// - skip_empty: If true, empty substrings are not included in the result
std::vector<std::string> split(std::string str, char del, bool skip_empty = false)
{
	// Vector to store the resulting substrings
	std::vector<std::string> tmp;
	// Temporary string to accumulate characters of the current substring
	std::string arg = "";

	// Iterate through each character in the input string
	for (std::string::size_type i = 0; i < str.size(); i++)
	{
		// Get the current character
		char c = str[i];

		// If the current character is the delimiter
		if (c == del)
		{
			// If not skipping empty substrings or arg is not empty, add it to the vector
			if (!skip_empty || !arg.empty())
			{
				tmp.push_back(arg);
				// Reset arg for the next substring
				arg = "";
			}
		}
		// If the current character is part of a substring
		else
		{
			arg.push_back(c);
		}
	}

	// Add the last substring if it's not empty or if we're not skipping empty substrings
	if (!skip_empty || !arg.empty())
	{
		tmp.push_back(arg);
	}

	// Return the vector of substrings
	return tmp;
}



// Function to format a ULONG number into a human-readable string with appropriate units
std::string format(ULONG num)
{
	// If the number is less than 1000, return it as is
	if (num < 1000)
		return std::to_string(num);

	// If the number is less than 1,024,000 (1000 KB), return it as kilobytes (K)
	if (num < 1024000)
		return std::to_string(num / 1024) + "K";

	// If the number is less than 1,048,576,000 (1000 MB), return it as megabytes (M)
	if (num < 1048576000)
		return std::to_string(num / 1048576) + "M";

	// If the number is less than 1,073,741,824,000 (1000 GB), return it as gigabytes (G)
	if (num < 1073741824000)
		return std::to_string(num / 1073741824) + "G";

	// If the number is less than 1,099,511,627,776,000 (1000 TB), return it as terabytes (T)
	if (num < 1099511627776000)
		return std::to_string(num / 1099511627776) + "T";

	// If the number is extremely large, return "inf" to indicate infinity or unmanageable size
	return "inf";
}


// Function to format an IP address for better readability
std::string format_ip(std::string ip)
{
	// Check if the IP address is the IPv6 unspecified address "::"
	if (ip.compare("::") == 0)
	{
		// If it is "::", return a formatted equivalent of the IPv4 unspecified address "0.0.0.0"
		return "  0.  0.  0.  0";
	}
	else
	{
		// Split the IP address into its octets using the split function
		std::vector<std::string> octets = split(ip, '.');

		// Check if the IP address has exactly 4 octets (valid IPv4 address)
		if (octets.size() == 4)
		{
			// For each octet, pad the string with spaces to ensure each is 3 characters long
			octets[0].insert(0, 3 - octets[0].length(), ' ');
			octets[1].insert(0, 3 - octets[1].length(), ' ');
			octets[2].insert(0, 3 - octets[2].length(), ' ');
			octets[3].insert(0, 3 - octets[3].length(), ' ');

			// Concatenate the formatted octets back into a single string
			return octets[0] + "." + octets[1] + "." + octets[2] + "." + octets[3];
		}
		else
		{
			// If the IP address is not a valid IPv4 address, return it as is
			return ip;
		}
	}
}


// Function to remove leading whitespace characters from a string
static inline void ltrim(std::string& s)
{
	// Use erase-remove idiom to remove leading spaces from the string
	// std::find_if is used to find the first non-space character
	s.erase(
		s.begin(),
		std::find_if(
			s.begin(),
			s.end(),
			[](unsigned char ch) {
				// Lambda function to check if a character is not a space
				return !std::isspace(ch);
			}
		)
	);
}

// Function to remove trailing whitespace characters from a string
static inline void rtrim(std::string& s)
{
	// Use the reverse iterator to find the first non-space character from the end
	auto it = std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
		// Lambda function to check if a character is not a space
		return !std::isspace(ch);
		});

	// Convert the reverse iterator to a regular iterator and erase from that point to the end
	s.erase(it.base(), s.end());
}

// Function to remove leading and trailing whitespace characters from a string
static inline void trim(std::string& s)
{
	// Remove leading whitespace characters
	ltrim(s);

	// Remove trailing whitespace characters
	rtrim(s);
}

// Function to truncate a string to a specified width
std::string truncate(std::string str, size_t width)
{
	// Check if the length of the string exceeds the specified width
	if (str.length() > width)
	{
		// If it does, return a substring from the start of the string up to the specified width
		return str.substr(0, width);
	}

	// If the string length does not exceed the specified width, return the original string
	return str;
}


// Function to validate if a given subnet string is in a valid format
bool validate_subnet(const std::string& subnet)
{
	// Check if the subnet is a wildcard, which is always valid
	if (subnet.compare("*") == 0)
		return true;

	// Split the subnet string by '/'
	std::vector<std::string> subnet_ = split(subnet, '/');

	// Split the network part by '.'
	std::vector<std::string> network = split(subnet_[0], '.');

	// Validate if the network part has exactly 4 octets
	if (network.size() != 4)
		return false;

	// Declare variables to store the octet values
	int network_a, network_b, network_c, network_d;

	// Try converting each octet from string to integer
	try
	{
		network_a = std::stoi(network[0]);
		network_b = std::stoi(network[1]);
		network_c = std::stoi(network[2]);
		network_d = std::stoi(network[3]);
	}
	catch (const std::exception&)
	{
		// Catch exceptions from invalid conversions (e.g., non-integer values)
		return false;
	}

	// Check if each octet is within the valid range [0, 255]
	if (network_a < 0 || network_a > 255) return false;
	if (network_b < 0 || network_b > 255) return false;
	if (network_c < 0 || network_c > 255) return false;
	if (network_d < 0 || network_d > 255) return false;

	// Validate the CIDR notation if present
	if (subnet_.size() == 1)
	{
		// No CIDR notation present, which is valid for subnet format
		return true;
	}
	else if (subnet_.size() == 2)
	{
		int cidr;
		try
		{
			cidr = std::stoi(subnet_[1]);
		}
		catch (const std::exception&)
		{
			// Catch exceptions from invalid conversions (e.g., non-integer values)
			return false;
		}
		// Check if the CIDR value is within the valid range [0, 32]
		if (cidr < 0 || cidr > 32)
			return false;
	}
	else
	{
		// If more than two parts are present, the subnet format is invalid
		return false;
	}

	// If all checks pass, the subnet format is valid
	return true;
}



// Function to check if an IP address matches a given subnet
bool ip_match(const std::string& ip, const std::string& subnet)
{
	// If the subnet is a wildcard, it matches any IP address
	if (subnet.compare("*") == 0)
		return true;

	// Split the IP address by '.'
	std::vector<std::string> ip_s = split(ip, '.');

	// Convert the IP address into a 32-bit integer
	UINT ip_ = std::stoi(ip_s[0]) << 24 |
		std::stoi(ip_s[1]) << 16 |
		std::stoi(ip_s[2]) << 8 |
		std::stoi(ip_s[3]);

	// Split the subnet into network and mask parts
	std::vector<std::string> subnet_ = split(subnet, '/');
	std::vector<std::string> network = split(subnet_[0], '.');

	// Check if the network part has exactly 4 octets
	if (network.size() != 4)
		return false;

	// Convert the network part into a 32-bit integer
	UINT network_ = std::stoi(network[0]) << 24 |
		std::stoi(network[1]) << 16 |
		std::stoi(network[2]) << 8 |
		std::stoi(network[3]);

	// Default mask to all 1's (32-bit)
	UINT mask = 0xFFFFFFFF;

	// Check if subnet has a mask part
	if (subnet_.size() == 1)
	{
		// No mask, so we only compare the network portion
		mask = 0xFFFFFFFF;
	}
	else if (subnet_.size() == 2)
	{
		// Convert CIDR mask to binary mask
		int cidr = std::stoi(subnet_[1]);
		if (cidr < 0 || cidr > 32)
			return false;
		mask = mask << (32 - cidr);
	}
	else
	{
		// Invalid subnet format
		return false;
	}

	// Check if the IP address matches the subnet using the mask
	return ~(mask & (ip_ ^ network_)) == 0xFFFFFFFF;
}


// Structure to hold the state of a network socket
struct socket_state
{
	std::string process = "";          // Name or identifier of the process using the socket
	std::string protocol = "";         // Protocol used by the socket (e.g., TCP, UDP)
	bool loopback = false;             // Indicates if the socket is a loopback socket
	std::string local_ip = "";         // Local IP address
	std::string local_port = "";       // Local port number
	std::string remote_ip = "";        // Remote IP address
	std::string remote_port = "";      // Remote port number
	std::string direction = "";        // Direction of traffic (e.g., incoming, outgoing)
	ULONG packets_in = 0;              // Number of incoming packets
	ULONG packets_out = 0;             // Number of outgoing packets
	ULONG bytes_in = 0;                // Number of incoming bytes
	ULONG bytes_out = 0;               // Number of outgoing bytes
	std::string status = "";           // Status of the socket (e.g., open, closed)
	std::string flags = "";            // Flags associated with the socket
	time_t heartbeat = 0;              // Timestamp for heartbeat or last activity
};

// Structure to define a rule for filtering network traffic
struct rule
{
	std::string protocol;   // Protocol (e.g., TCP, UDP)
	std::string local_ip;   // Local IP address to match
	std::string local_port; // Local port number to match
	std::string remote_ip;  // Remote IP address to match
	std::string remote_port;// Remote port number to match
	std::string process;    // Process name or identifier
	std::string policy;     // Policy associated with the rule
};

// Structure to define a loopback rule for filtering loopback traffic
struct loopback_rule
{
	std::string protocol;       // Protocol (e.g., TCP, UDP)
	std::string client_ip;      // Client IP address
	std::string client_port;    // Client port number
	std::string client_process; // Process name or identifier for the client
	std::string server_ip;      // Server IP address
	std::string server_port;    // Server port number
	std::string server_process; // Process name or identifier for the server
	std::string policy;         // Policy associated with the loopback rule
};

// Constants for buffer sizes and timeouts
#define MAXBUF 65536            // Maximum buffer size (64KB)
#define INET6_ADDRSTRLEN 45     // Length of IPv6 address string representation

// Timeout values in seconds
UINT TIMEOUT = 5;              // General timeout
UINT TCP_TIMEOUT = 300;        // Timeout for TCP connections
UINT UDP_TIMEOUT = 10;         // Timeout for UDP connections
UINT REFRESH_INTERVAL = 1;     // Refresh interval for updating data

// Global variables for application state
int mode = 0;                  // Mode of operation (e.g., normal, debug)
bool paused = false;           // Flag to indicate if the application is paused

HANDLE s_handle;               // Handle for socket operations
HANDLE n_handle;               // Handle for network operations
HANDLE console;                // Handle for console operations

// Collections for storing rules and states
std::vector<rule> in_rules = {};              // List of incoming traffic rules
std::vector<rule> out_rules = {};             // List of outgoing traffic rules
std::vector<loopback_rule> loopback_rules = {};// List of loopback rules

std::list<std::string> sockets_order = {};    // List of socket identifiers in order
std::unordered_map<std::string, socket_state*> sockets = {}; // Mapping of socket identifiers to their states

std::unordered_map<std::string, std::string> processByPort_ = {}; // Mapping of ports to process names

time_t activestat_heartbeat = 0; // Timestamp for the last activity or heartbeat

// Mutexes for thread safety
std::mutex mtx_sockets;          // Mutex for socket operations
std::mutex mtx_rules;            // Mutex for rule operations
std::mutex mtx_processByPort;    // Mutex for process-to-port mapping
std::mutex mtx_console;          // Mutex for console operations
std::mutex mtx_queued;           // Mutex for queued operations




// Function to format and log information to the console
void log_(time_t timestamp, const std::string& protocol, const std::string& direction,
	const std::string& local_ip, const std::string& local_port,
	const std::string& remote_ip, const std::string& remote_port,
	const std::string& process, const std::string& action)
{
	// Check if logging is enabled (mode == 1)
	if (mode == 1)
	{
		// Convert timestamp to local time
		struct tm timestamp_;
		localtime_s(&timestamp_, &timestamp);

		// Format the timestamp to "HH:MM:SS"
		char timestamp_f[21];
		strftime(timestamp_f, 21, "%H:%M:%S", &timestamp_);

		// Normalize action value
		std::string normalized_action = action;
		if (normalized_action.compare("ACCEPT_HIDE") == 0)
			normalized_action = "ACCEPT";

		// Lock the mutex to ensure exclusive access to the console
		mtx_console.lock();

		// Retrieve console screen buffer info
		CONSOLE_SCREEN_BUFFER_INFO csbi;
		GetConsoleScreenBufferInfo(console, &csbi);
		short rows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
		short columns = csbi.srWindow.Right - csbi.srWindow.Left + 1;

		// Set console text color based on action
		if (normalized_action.compare("ACCEPT") == 0)
			SetConsoleTextAttribute(console, 10); // Green for ACCEPT
		else
			SetConsoleTextAttribute(console, 12); // Red for other actions

		// Output formatted log entry to the console
		std::cout
			<< std::left
			<< timestamp_f << " "                           // Time of the log entry
			<< std::setw(6) << protocol << " "              // Protocol (e.g., TCP, UDP)
			<< std::right
			<< format_ip(local_ip) << ":" << std::setw(5) << local_port // Local IP and port
			<< direction                                  // Direction (e.g., ->, <-)
			<< format_ip(remote_ip) << ":" << std::setw(5) << remote_port // Remote IP and port
			<< " "
			<< std::left
			<< std::setw(7) << normalized_action << " "   // Action (e.g., ACCEPT, DENY)
			<< std::setw(static_cast<std::streamsize>(columns) - 70)  // Adjust width for process name
			<< truncate(process, static_cast<std::streamsize>(columns) - 70) // Process name (truncated if needed)
			<< std::endl
			<< std::right;

		// Reset console text color to default
		SetConsoleTextAttribute(console, 15);

		// Unlock the mutex
		mtx_console.unlock();
	}
}



// Function to get the process name by its ID
std::string processById(DWORD id)
{
	// Open the process with the query limited information access
	HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, id);

	// Buffer to store the path of the process executable
	DWORD path_len = 0;
	char path[MAX_PATH + 1];
	std::string filename = "";

	// Check if the process handle is valid
	if (process != NULL)
	{
		// Get the path of the executable file for the process
		path_len = GetProcessImageFileNameA(process, path, sizeof(path));

		// Close the handle to the process
		CloseHandle(process);
	}

	// Check if the path length is non-zero, indicating that the path was retrieved successfully
	if (path_len != 0)
	{
		// Extract the filename from the path
		char* filename_ = PathFindFileNameA(path);

		// Convert the filename to a std::string
		filename = std::string(filename_);
	}
	// Special case for process ID 4 (System process)
	else if (id == 4)
	{
		filename = "System";
	}
	// Handle the case where the process path could not be retrieved
	else
	{
		filename = "pid=" + std::to_string(id);
	}

	// Return the filename or process name
	return filename;
}



// Function to get the process name associated with a given port and protocol
std::string processByPort(const std::string& protocol, const std::string& ip, const std::string& port)
{
	// Construct the two possible keys for the map
	std::string tuple1 = protocol + " " + ip + ":" + port;
	std::string tuple2 = protocol + " 0.0.0.0:" + port;

	std::string process = "";

	// Lock the mutex to ensure exclusive access to the processByPort_ map
	mtx_processByPort.lock();

	// Check if the first tuple exists in the map
	if (processByPort_.find(tuple1) != processByPort_.cend())
	{
		process = processByPort_[tuple1];
	}
	// Check if the second tuple exists in the map
	else if (processByPort_.find(tuple2) != processByPort_.cend())
	{
		process = processByPort_[tuple2];
	}

	// Unlock the mutex to allow other threads to access the map
	mtx_processByPort.unlock();

	// Return the process name, or an empty string if not found
	return process;
}

// Function to update the status of a socket based on the provided flags and direction
void socket_update_status(socket_state* socket_state_, const std::string& direction, bool fin, bool syn, bool rst, bool psh, bool ack)
{
	// Check if the protocol is UDP
	if (socket_state_->protocol.compare("UDP") == 0)
	{
		// Handle UDP-specific status updates
		if (socket_state_->status.compare("CNCT") == 0)
		{
			// If the status is "CNCT" and the direction has changed, update status to "EST"
			if (socket_state_->direction.compare(direction) != 0)
			{
				socket_state_->status = "EST";
			}
		}
		else if (socket_state_->status.compare("TOUT") == 0)
		{
			// If the status is "TOUT", update status to "EST"
			socket_state_->status = "EST";
		}
	}
	// Check if the protocol is TCP
	else if (socket_state_->protocol.compare("TCP") == 0)
	{
		// Handle TCP-specific status updates
		if (rst)
		{
			// If the RST flag is set, update status based on the direction
			if (direction.compare("->") == 0)
			{
				socket_state_->status = "LRST"; // Local RST
			}
			else if (direction.compare("<-") == 0)
			{
				socket_state_->status = "RRST"; // Remote RST
			}
		}
		else if (socket_state_->status.compare("CNCT") == 0)
		{
			// If the status is "CNCT" and SYN and ACK flags are set and direction has changed, update status to "EST"
			if (socket_state_->direction.compare(direction) != 0 && syn && ack)
			{
				socket_state_->status = "EST"; // Established
			}
		}
		else if (socket_state_->status.compare("EST") == 0)
		{
			// If the status is "EST" and the FIN flag is set, update status based on the direction
			if (fin)
			{
				if (direction.compare("->") == 0)
				{
					socket_state_->status = "LFIN"; // Local FIN
				}
				else if (direction.compare("<-") == 0)
				{
					socket_state_->status = "RFIN"; // Remote FIN
				}
			}
		}
		else if (socket_state_->status.compare("LFIN") == 0)
		{
			// If the status is "LFIN" and the direction is incoming with FIN flag set, update status to "CLSD"
			if (direction.compare("<-") == 0 && fin)
			{
				socket_state_->status = "CLSD"; // Closed
			}
		}
		else if (socket_state_->status.compare("RFIN") == 0)
		{
			// If the status is "RFIN" and the direction is outgoing with FIN flag set, update status to "CLSD"
			if (direction.compare("->") == 0 && fin)
			{
				socket_state_->status = "CLSD"; // Closed
			}
		}
		else if (socket_state_->status.compare("CLSD") == 0)
		{
			// If the status is "CLSD" and direction matches and SYN flag is set without ACK, update status to "CNCT"
			if (socket_state_->direction.compare(direction) == 0 && syn && !ack)
			{
				socket_state_->status = "CNCT"; // Connect
			}
		}
		else if (socket_state_->status.compare("TOUT") == 0)
		{
			// If the status is "TOUT", update status to "EST"
			socket_state_->status = "EST";
		}
	}
}



// Function to determine the action for a socket based on rules
std::string socket_action(const std::string& process, const std::string& direction, const std::string& protocol,
	const std::string& local_ip, const std::string& local_port,
	const std::string& remote_ip, const std::string& remote_port)
{
	// Lock the mutex to ensure thread safety while accessing the rules
	mtx_rules.lock();

	// Vector to hold the appropriate rules based on the direction
	std::vector<rule> table;

	// Determine which set of rules to use based on the direction
	if (direction.compare("->") == 0)
		table = out_rules;   // Use outgoing rules
	else if (direction.compare("<-") == 0)
		table = in_rules;    // Use incoming rules

	// Iterate over the selected set of rules
	for (size_t i = 0; i < table.size(); i++)
	{
		// Retrieve the current rule
		rule rule = table[i];

		// Check if the rule's process matches (or if it is wildcard "*")
		if (rule.process.compare("*") != 0 && rule.process.compare(process) != 0)
			continue;

		// Check if the rule's protocol matches (or if it is wildcard "*")
		if (rule.protocol.compare("*") != 0 && rule.protocol.compare(protocol) != 0)
			continue;

		// Check if the local IP matches the rule
		if (!ip_match(local_ip, rule.local_ip))
			continue;

		// Check if the rule's local port matches (or if it is wildcard "*")
		if (rule.local_port.compare("*") != 0 && rule.local_port.compare(local_port) != 0)
			continue;

		// Check if the remote IP matches the rule
		if (!ip_match(remote_ip, rule.remote_ip))
			continue;

		// Check if the rule's remote port matches (or if it is wildcard "*")
		if (rule.remote_port.compare("*") != 0 && rule.remote_port.compare(remote_port) != 0)
			continue;

		// Unlock the mutex as we have found a matching rule
		mtx_rules.unlock();

		// Return the policy associated with the matching rule
		return rule.policy;
	}

	// Unlock the mutex as no matching rule was found
	mtx_rules.unlock();

	// Return "DROP" if no matching rule is found (default action)
	return "DROP";
	// Optionally, you could return "ACCEPT" instead, depending on your requirements
}



// Function to process a network packet
bool process_packet(time_t now, const std::string& process, const std::string& direction,
	const std::string& protocol, const std::string& local_ip, const std::string& local_port,
	const std::string& remote_ip, const std::string& remote_port,
	UINT packet_len, bool fin, bool syn, bool rst, bool psh, bool ack,
	bool packet, bool* reject)
{
	// Create a unique tuple string for identifying the socket
	std::string tuple = protocol + " " + local_ip + ":" + local_port + " " + remote_ip + ":" + remote_port;

	// Pointer to hold the socket state
	socket_state* socket_state_;

	// Initialize reject flag to false
	*reject = false;

	// Lock mutex to ensure thread safety while accessing the sockets map
	mtx_sockets.lock();

	// Check if the socket (tuple) exists in the map
	if (sockets.find(tuple) == sockets.cend())
	{
		bool accept = false;
		bool hide = false;

		// Determine if the packet should be accepted based on protocol and flags
		if ((protocol.compare("TCP") == 0 && syn && !ack) || protocol.compare("UDP") == 0)
		{
			// Determine action for the socket based on rules
			std::string action = socket_action(process, direction, protocol, local_ip, local_port, remote_ip, remote_port);

			// Log the action
			log_(now, protocol, direction, local_ip, local_port, remote_ip, remote_port, process, action);

			// Set the accept and hide flags based on the action
			if (action.compare("ACCEPT") == 0)
			{
				accept = true;
			}
			else if (action.compare("ACCEPT_HIDE") == 0)
			{
				accept = true;
				hide = true;
			}
			else if (action.compare("REJECT") == 0)
			{
				*reject = true;
			}
		}

		// If not accepted, unlock the mutex and return false
		if (!accept)
		{
			mtx_sockets.unlock();
			return false;
		}

		// Allocate a new socket_state object
		socket_state_ = new socket_state();

		// Initialize the socket state with packet details
		socket_state_->process = process;
		socket_state_->protocol = protocol;
		socket_state_->loopback = false; // Assuming non-loopback by default
		socket_state_->local_ip = local_ip;
		socket_state_->local_port = local_port;
		socket_state_->remote_ip = remote_ip;
		socket_state_->remote_port = remote_port;
		socket_state_->direction = direction;
		socket_state_->status = "CNCT"; // Set initial status as "CNCT" (connecting)
		socket_state_->heartbeat = now; // Set the current time as the heartbeat

		// Add the new socket state to the sockets map
		sockets[tuple] = socket_state_;

		// If not hiding, add the socket tuple to the front of the order list
		if (!hide) sockets_order.push_front(tuple);
	}
	else
	{
		// If the socket already exists, get its state
		socket_state_ = sockets[tuple];

		// Update the heartbeat time for the existing socket state
		socket_state_->heartbeat = now;

		// Update the status of the socket based on the packet flags
		socket_update_status(socket_state_, direction, fin, syn, rst, psh, ack);
	}

	// Update packet and byte counts based on direction
	if (packet)
	{
		if (direction.compare("->") == 0)
		{
			// Increment outgoing packet and byte counts
			socket_state_->packets_out++;
			socket_state_->bytes_out += packet_len;
		}
		else if (direction.compare("<-") == 0)
		{
			// Increment incoming packet and byte counts
			socket_state_->packets_in++;
			socket_state_->bytes_in += packet_len;
		}
	}

	// Move the socket tuple to the front of the order list to mark it as most recent
	auto i = std::find(sockets_order.begin(), sockets_order.end(), tuple);
	if (i != sockets_order.end())
	{
		i = sockets_order.erase(i); // Remove from current position
		sockets_order.push_front(tuple); // Add to the front
	}

	// Unlock mutex after completing operations
	mtx_sockets.unlock();

	// Return true indicating successful processing
	return true;
}



// Function to determine the action for a loopback socket based on rules
std::string loopback_socket_action(const std::string& protocol, const std::string& client_ip, const std::string& client_port,
	const std::string& client_process, const std::string& server_ip, const std::string& server_port,
	const std::string& server_process)
{
	// Lock the mutex to ensure thread safety while accessing the rules vector
	mtx_rules.lock();

	// Create a local copy of the loopback rules vector
	std::vector<loopback_rule> table = loopback_rules;

	// Iterate through each rule in the table
	for (size_t i = 0; i < table.size(); i++)
	{
		// Retrieve the current rule
		loopback_rule rule = table[i];

		// Check if the rule protocol matches or is a wildcard
		if (rule.protocol.compare("*") != 0 && rule.protocol.compare(protocol) != 0) continue;

		// Check if the client IP matches the rule or is a wildcard
		if (!ip_match(client_ip, rule.client_ip)) continue;

		// Check if the client port matches the rule or is a wildcard
		if (rule.client_port.compare("*") != 0 && rule.client_port.compare(client_port) != 0) continue;

		// Check if the client process matches the rule or is a wildcard
		if (rule.client_process.compare("*") != 0 && rule.client_process.compare(client_process) != 0) continue;

		// Check if the server IP matches the rule or is a wildcard
		if (!ip_match(server_ip, rule.server_ip)) continue;

		// Check if the server port matches the rule or is a wildcard
		if (rule.server_port.compare("*") != 0 && rule.server_port.compare(server_port) != 0) continue;

		// Check if the server process matches the rule or is a wildcard
		if (rule.server_process.compare("*") != 0 && rule.server_process.compare(server_process) != 0) continue;

		// Unlock the mutex before returning the policy
		mtx_rules.unlock();

		// Return the policy associated with the matching rule
		return rule.policy;
	}

	// Unlock the mutex if no rule matches
	mtx_rules.unlock();

	// Return "DROP" if no matching rule was found
	return "DROP";
}


// Function to process a loopback packet and update the state of sockets
bool process_loopback_packet(time_t now, const std::string& protocol,
	const std::string& client_ip, const std::string& client_port,
	const std::string& client_process, const std::string& server_ip,
	const std::string& server_port, const std::string& server_process,
	UINT packet_len, bool fin, bool syn, bool rst, bool psh, bool ack,
	bool packet, bool* reject)
{
	// Lock the mutex to ensure thread safety while accessing shared resources
	mtx_sockets.lock();

	// Construct tuples representing the client-to-server and server-to-client connections
	std::string out_tuple = protocol + " " + client_ip + ":" + client_port + " " + server_ip + ":" + server_port;
	std::string in_tuple = protocol + " " + server_ip + ":" + server_port + " " + client_ip + ":" + client_port;

	// Pointer to hold the state of the socket
	socket_state* socket_state_;

	// Initialize the reject flag to false
	*reject = false;

	// Check if the outgoing socket tuple exists in the socket map
	if (sockets.find(out_tuple) == sockets.cend())
	{
		// Initialize variables to determine the action and status
		bool accept = false;
		bool hide = false;
		std::string action;
		std::string status;

		// Determine the initial status based on the protocol and flags
		if ((protocol.compare("TCP") == 0 && syn && !ack) || protocol.compare("UDP") == 0)
		{
			status = "CNCT"; // Connection status for new connections

			// Get the action to be taken based on loopback rules
			action = loopback_socket_action(protocol, client_ip, client_port, client_process, server_ip, server_port, server_process);

			// Log the connection attempt for both directions
			log_(now, protocol, "->", client_ip, client_port, server_ip, server_port, client_process, action);
			log_(now, protocol, "<-", server_ip, server_port, client_ip, client_port, server_process, action);
		}
		else
		{
			status = "EST"; // Connection status for existing connections

			// Get the action to be taken based on loopback rules
			action = loopback_socket_action(protocol, client_ip, client_port, client_process, server_ip, server_port, server_process);
		}

		// Determine whether to accept, hide, or reject the packet based on the action
		if (action.compare("ACCEPT") == 0)
		{
			accept = true;
		}
		else if (action.compare("ACCEPT_HIDE") == 0)
		{
			accept = true;
			hide = true;
		}
		else if (action.compare("REJECT") == 0)
		{
			*reject = true;
		}

		// If the packet is not accepted, unlock the mutex and return false
		if (!accept)
		{
			mtx_sockets.unlock();
			return false;
		}

		// Handle the outgoing connection (client-to-server)

		// Create a new socket state for the outgoing connection
		socket_state_ = new socket_state();
		socket_state_->process = client_process;
		socket_state_->protocol = protocol;
		socket_state_->loopback = true;
		socket_state_->local_ip = client_ip;
		socket_state_->local_port = client_port;
		socket_state_->remote_ip = server_ip;
		socket_state_->remote_port = server_port;
		socket_state_->direction = "->";
		socket_state_->status = status;
		socket_state_->heartbeat = now;

		// Add the socket state to the map and update the order list
		sockets[out_tuple] = socket_state_;
		if (!hide) sockets_order.push_front(out_tuple);

		// Update packet and byte counters if this is a packet
		if (packet)
		{
			socket_state_->packets_out++;
			socket_state_->bytes_out += packet_len;
		}

		// Handle the incoming connection (server-to-client)

		// Create a new socket state for the incoming connection
		socket_state_ = new socket_state();
		socket_state_->process = server_process;
		socket_state_->protocol = protocol;
		socket_state_->loopback = true;
		socket_state_->local_ip = server_ip;
		socket_state_->local_port = server_port;
		socket_state_->remote_ip = client_ip;
		socket_state_->remote_port = client_port;
		socket_state_->direction = "<-";
		socket_state_->status = status;
		socket_state_->heartbeat = now;

		// Add the socket state to the map and update the order list
		sockets[in_tuple] = socket_state_;
		if (!hide) sockets_order.push_front(in_tuple);

		// Update packet and byte counters if this is a packet
		if (packet)
		{
			socket_state_->packets_in++;
			socket_state_->bytes_in += packet_len;
		}
	}
	else
	{
		// Handle the case where the outgoing tuple already exists in the map
		socket_state_ = sockets[out_tuple];
		socket_state_->heartbeat = now;
		socket_update_status(socket_state_, "->", fin, syn, rst, psh, ack);

		// Update packet and byte counters if this is a packet
		if (packet)
		{
			socket_state_->packets_out++;
			socket_state_->bytes_out += packet_len;
		}

		// Handle the corresponding incoming tuple if it exists
		if (sockets.find(in_tuple) != sockets.cend()) // Check if the incoming tuple exists
		{
			socket_state_ = sockets[in_tuple];
			socket_state_->heartbeat = now;
			socket_update_status(socket_state_, "<-", fin, syn, rst, psh, ack);

			// Update packet and byte counters if this is a packet
			if (packet)
			{
				socket_state_->packets_in++;
				socket_state_->bytes_in += packet_len;
			}
		}
	}

	// Update the order of the socket tuples in the order list
	auto i = std::find(sockets_order.begin(), sockets_order.end(), out_tuple);
	if (i != sockets_order.end())
	{
		sockets_order.erase(i);
		sockets_order.push_front(out_tuple);
	}

	i = std::find(sockets_order.begin(), sockets_order.end(), in_tuple);
	if (i != sockets_order.end())
	{
		sockets_order.erase(i);
		sockets_order.push_front(in_tuple);
	}

	// Unlock the mutex before returning
	mtx_sockets.unlock();

	return true;
}

typedef struct
{
	WINDIVERT_IPHDR ip;    // IPv4 header
	WINDIVERT_TCPHDR tcp;  // TCP header
} TCPPACKET, * PTCPPACKET;


typedef struct
{
	WINDIVERT_IPV6HDR ipv6; // IPv6 header
	WINDIVERT_TCPHDR tcp;   // TCP header
} TCPV6PACKET, * PTCPV6PACKET;

typedef struct
{
	WINDIVERT_IPHDR ip;   // IPv4 header
	WINDIVERT_ICMPHDR icmp; // ICMP header
	UINT8 data[];         // ICMP data (variable length)
} ICMPPACKET, * PICMPPACKET;


typedef struct
{
	WINDIVERT_IPV6HDR ipv6;  // IPv6 header
	WINDIVERT_ICMPV6HDR icmpv6; // ICMPv6 header
	UINT8 data[];            // ICMPv6 data (variable length)
} ICMPV6PACKET, * PICMPV6PACKET;

/*
 * Initialize a PACKET for IPv4.
 */
static void PacketIpInit(PWINDIVERT_IPHDR packet)
{
	// Zero out the entire packet structure to ensure no residual data
	memset(packet, 0, sizeof(WINDIVERT_IPHDR));

	// Set the IP version to IPv4 (4)
	packet->Version = 4;

	// Calculate and set the header length in 32-bit words.
	// The header length is the size of the IP header divided by the size of a UINT32.
	// For a standard IPv4 header, this is 5 (20 bytes).
	packet->HdrLength = sizeof(WINDIVERT_IPHDR) / sizeof(UINT32);

	// Set the Identification field to a specific value (0xDEAD).
	// This is used to uniquely identify the group of fragments of a single IP datagram.
	// The value is converted from network byte order to host byte order.
	packet->Id = ntohs(0xDEAD);

	// Set the Time-To-Live (TTL) field to 64.
	// TTL specifies the maximum number of hops (routers) the packet can pass through before being discarded.
	// It helps to prevent packets from looping indefinitely in case of routing loops.
	packet->TTL = 64;
}


/*
 * Initialize a TCPPACKET.
 * This function initializes both the IP header and the TCP header within the TCPPACKET structure.
 */
static void PacketIpTcpInit(PTCPPACKET packet)
{
	// Zero out the entire TCPPACKET structure to ensure no residual data
	memset(packet, 0, sizeof(TCPPACKET));

	// Initialize the IP header portion of the TCPPACKET
	PacketIpInit(&packet->ip);

	// Set the total length of the IP packet including the TCP header
	// This is calculated as the size of the entire TCPPACKET structure.
	// The length field is in network byte order (big-endian), so we use htons to convert.
	packet->ip.Length = htons(sizeof(TCPPACKET));

	// Set the IP protocol field to indicate that this is a TCP packet
	// The IPPROTO_TCP constant specifies that the payload of the IP packet is a TCP segment.
	packet->ip.Protocol = IPPROTO_TCP;

	// Set the TCP header length in 32-bit words
	// The length is calculated as the size of the TCP header divided by the size of a UINT32.
	// This is typically 5 for a standard TCP header (20 bytes).
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}

/*
 * Initialize an ICMPPACKET.
 * This function initializes the IP header and the ICMP header within the ICMPPACKET structure.
 */
static void PacketIpIcmpInit(PICMPPACKET packet)
{
	// Zero out the entire ICMPPACKET structure to ensure no residual data
	memset(packet, 0, sizeof(ICMPPACKET));

	// Initialize the IP header portion of the ICMPPACKET
	PacketIpInit(&packet->ip);

	// Set the IP protocol field to indicate that this is an ICMP packet
	// The IPPROTO_ICMP constant specifies that the payload of the IP packet is an ICMP message.
	packet->ip.Protocol = IPPROTO_ICMP;
}


/*
 * Initialize a PACKETV6.
 * This function initializes the IPv6 header within the PACKETV6 structure.
 */
static void PacketIpv6Init(PWINDIVERT_IPV6HDR packet)
{
	// Zero out the entire IPv6 header structure to ensure no residual data
	memset(packet, 0, sizeof(WINDIVERT_IPV6HDR));

	// Set the IPv6 version field to indicate IPv6
	// The Version field is set to 6 for IPv6 packets.
	packet->Version = 6;

	// Set the Hop Limit field to the default value
	// Hop Limit specifies the maximum number of hops (routers) a packet can pass through.
	// The default value of 64 is a common setting for IPv6 packets.
	packet->HopLimit = 64;
}


/*
 * Initialize a TCPV6PACKET.
 * This function initializes the IPv6 and TCP headers within the TCPV6PACKET structure.
 */
static void PacketIpv6TcpInit(PTCPV6PACKET packet)
{
	// Zero out the entire TCPV6PACKET structure to ensure no residual data
	memset(packet, 0, sizeof(TCPV6PACKET));

	// Initialize the IPv6 header
	PacketIpv6Init(&packet->ipv6);

	// Set the Length field in the IPv6 header to the size of the TCP header
	// This specifies the length of the TCP header data in the IPv6 packet.
	packet->ipv6.Length = htons(sizeof(WINDIVERT_TCPHDR));

	// Set the NextHdr field in the IPv6 header to indicate that the next header is TCP
	// IPPROTO_TCP is the protocol number for TCP in IPv6.
	packet->ipv6.NextHdr = IPPROTO_TCP;

	// Set the HdrLength field in the TCP header
	// This specifies the length of the TCP header in terms of 32-bit words.
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}



/*Initialize an ICMPV6PACKET.
* This function initializes the IPv6 and ICMPv6 headers within the ICMPV6PACKET structure.
*/
static void PacketIpv6Icmpv6Init(PICMPV6PACKET packet)
{
	// Zero out the entire ICMPV6PACKET structure to ensure no residual data
	memset(packet, 0, sizeof(ICMPV6PACKET));

	// Initialize the IPv6 header
	PacketIpv6Init(&packet->ipv6);

	// Set the NextHdr field in the IPv6 header to indicate that the next header is ICMPv6
	// IPPROTO_ICMPV6 is the protocol number for ICMPv6.
	packet->ipv6.NextHdr = IPPROTO_ICMPV6;

	// No need to set ICMPv6 header fields here as they are typically initialized separately
}

// Declare and initialize a TCPPACKET instance and its pointer
TCPPACKET reset0; // Create a TCPPACKET instance named reset0
PTCPPACKET reset = &reset0; // Create a pointer to the TCPPACKET instance

// Declare a buffer for an ICMPPACKET and cast it to a PICMPPACKET
UINT8 dnr0[sizeof(ICMPPACKET) + 0x0F * sizeof(UINT32) + 8 + 1];
// Allocate a buffer that is large enough to hold an ICMPPACKET
// Additionally, add extra space for potential padding or data
PICMPPACKET dnr = (PICMPPACKET)dnr0; // Cast the buffer to an ICMPPACKET pointer

// Declare and initialize a TCPV6PACKET instance and its pointer
TCPV6PACKET resetv6_0; // Create a TCPV6PACKET instance named resetv6_0
PTCPV6PACKET resetv6 = &resetv6_0; // Create a pointer to the TCPV6PACKET instance

// Declare a buffer for an ICMPV6PACKET and cast it to a PICMPV6PACKET
UINT8 dnrv6_0[sizeof(ICMPV6PACKET) + sizeof(WINDIVERT_IPV6HDR) +
sizeof(WINDIVERT_TCPHDR)];
// Allocate a buffer that is large enough to hold an ICMPV6PACKET
// Include space for the IPv6 header and TCP header
PICMPV6PACKET dnrv6 = (PICMPV6PACKET)dnrv6_0; // Cast the buffer to an ICMPV6PACKET pointer

void load()
{
	ifstream file; // File stream for reading configuration files
	string line;   // Line buffer for reading lines from the file
	UINT lineno;   // Line number counter for reporting errors

	// Continuously attempt to validate settings and rules until successful
	for (; ; )
	{
		bool error = false; // Flag to indicate if any validation errors were found

		cout << "  VALIDATING SETTINGS: " << endl;

		// Open and read the settings file
		file = ifstream("settings.txt");
		lineno = 1;
		while (getline(file, line))
		{
			vector<string> args = split_args(line); // Split the line into arguments
			if (args.size() == 0); // Skip empty lines
			else if (args.size() == 2) // Expected format: key value
			{
				int value;
				try
				{
					value = stoi(args[1]); // Convert the second argument to an integer
					if (value < 0)
					{
						cout << "    ERROR at line " << lineno << ": Invalid value" << endl;
						error = true;
					}
				}
				catch (const std::exception&)
				{
					cout << "    ERROR at line " << lineno << ": Invalid value" << endl;
					error = true;
				}
			}
			else
			{
				cout << "    ERROR at line " << lineno << ": Expected 2 arguments" << endl;
				error = true;
			}
			lineno++;
		}

		cout << endl;

		cout << "  VALIDATING RULE TABLES: " << endl << endl;

		// Validate loopback rules from loopback.txt
		cout << "    LOOPBACK: " << endl;
		file = ifstream("loopback.txt");
		lineno = 1;
		while (getline(file, line))
		{
			vector<string> args = split_args(line); // Split the line into arguments
			if (args.size() == 0); // Skip empty lines
			else if (args.size() == 8) // Expected format: protocol client_ip client_port client_process server_ip server_port server_process policy
			{
				if (!validate_subnet(args[1])) // Validate client IP address
				{
					cout << "      ERROR at line " << lineno << ": Client IP is invalid" << endl;
					error = true;
				}
				if (!validate_subnet(args[4])) // Validate server IP address
				{
					cout << "      ERROR at line " << lineno << ": Server IP is invalid" << endl;
					error = true;
				}
			}
			else
			{
				cout << "      ERROR at line " << lineno << ": Expected 8 arguments" << endl;
				error = true;
			}
			lineno++;
		}

		cout << endl;

		// Validate inbound rules from in.txt
		cout << "    INBOUND: " << endl;
		file = ifstream("in.txt");
		lineno = 1;
		while (getline(file, line))
		{
			vector<string> args = split_args(line); // Split the line into arguments
			if (args.size() == 0); // Skip empty lines
			else if (args.size() == 7) // Expected format: protocol local_ip local_port remote_ip remote_port process policy
			{
				if (!validate_subnet(args[1])) // Validate local IP address
				{
					cout << "ERROR at line " << lineno << ": Local IP is invalid" << endl;
					error = true;
				}
				if (!validate_subnet(args[3])) // Validate remote IP address
				{
					cout << "ERROR at line " << lineno << ": Remote IP is invalid" << endl;
					error = true;
				}
			}
			else
			{
				cout << "ERROR at line " << lineno << ": Expected 7 arguments" << endl;
				error = true;
			}
			lineno++;
		}

		cout << endl;

		// Validate outbound rules from out.txt
		cout << "    OUTBOUND:" << endl;
		file = ifstream("out.txt");
		lineno = 1;
		while (getline(file, line))
		{
			vector<string> args = split_args(line); // Split the line into arguments
			if (args.size() == 0); // Skip empty lines
			else if (args.size() == 7) // Expected format: protocol local_ip local_port remote_ip remote_port process policy
			{
				rule rule; // Temporary rule object for processing
				if (!validate_subnet(args[1])) // Validate local IP address
				{
					cout << "      ERROR at line " << lineno << ": Local IP is invalid" << endl;
					error = true;
				}
				if (!validate_subnet(args[3])) // Validate remote IP address
				{
					cout << "      ERROR at line " << lineno << ": Remote IP is invalid" << endl;
					error = true;
				}
			}
			else
			{
				cout << "      ERROR at line " << lineno << ": Expected 7 arguments" << endl;
				error = true;
			}
			lineno++;
		}

		cout << endl;

		if (error)
		{
			// If errors were found during validation, display a message and wait for user input
			cout << "  FAILED!" << endl << endl;
			cout << "  Fix errors and press any key...";
			_getch(); // Wait for user input to proceed after fixing errors
		}
		else
		{
			// If no errors were found, proceed to load the settings and rules
			cout << "  PASSED!" << endl << endl;
			break; // Exit the loop as validation was successful
		}
	}

	cout << endl;

	cout << "  LOADING SETTINGS & RULE TABLES: ";

	// Load settings from the settings file
	file = ifstream("settings.txt");
	while (getline(file, line))
	{
		vector<string> args = split_args(line); // Split the line into arguments
		if (args.size() == 0); // Skip empty lines
		else if (args.size() == 2) // Expected format: key value
		{
			if (args[0].compare("TIMEOUT") == 0)
				TIMEOUT = stoi(args[1]); // Set the TIMEOUT value
			else if (args[0].compare("TCP_TIMEOUT") == 0)
				TCP_TIMEOUT = stoi(args[1]); // Set the TCP_TIMEOUT value
			else if (args[0].compare("UDP_TIMEOUT") == 0)
				UDP_TIMEOUT = stoi(args[1]); // Set the UDP_TIMEOUT value
		}
	}

	mtx_rules.lock(); // Lock mutex to ensure thread-safe access to rule tables

	// Clear existing rules from the vectors
	loopback_rules.clear();
	in_rules.clear();
	out_rules.clear();

	// Load loopback rules from loopback.txt
	file = ifstream("loopback.txt");
	while (getline(file, line))
	{
		vector<string> args = split_args(line); // Split the line into arguments
		if (args.size() == 0); // Skip empty lines
		else if (args.size() == 8) // Expected format: protocol client_ip client_port client_process server_ip server_port server_process policy
		{
			loopback_rule rule; // Temporary loopback rule object
			rule.protocol = args[0];
			rule.client_ip = args[1];
			rule.client_port = args[2];
			rule.client_process = args[3];
			rule.server_ip = args[4];
			rule.server_port = args[5];
			rule.server_process = args[6];
			rule.policy = args[7];
			loopback_rules.push_back(rule); // Add rule to loopback_rules vector
		}
	}

	// Load inbound rules from in.txt
	file = ifstream("in.txt");
	while (getline(file, line))
	{
		vector<string> args = split_args(line); // Split the line into arguments
		if (args.size() == 0); // Skip empty lines
		else if (args.size() == 7) // Expected format: protocol local_ip local_port remote_ip remote_port process policy
		{
			rule rule; // Temporary inbound rule object
			rule.protocol = args[0];
			rule.local_ip = args[1];
			rule.local_port = args[2];
			rule.remote_ip = args[3];
			rule.remote_port = args[4];
			rule.process = args[5];
			rule.policy = args[6];
			in_rules.push_back(rule); // Add rule to in_rules vector
		}
	}

	// Load outbound rules from out.txt
	file = ifstream("out.txt");
	while (getline(file, line))
	{
		vector<string> args = split_args(line); // Split the line into arguments
		if (args.size() == 0); // Skip empty lines
		else if (args.size() == 7) // Expected format: protocol local_ip local_port remote_ip remote_port process policy
		{
			rule rule; // Temporary outbound rule object
			rule.protocol = args[0];
			rule.local_ip = args[1];
			rule.local_port = args[2];
			rule.remote_ip = args[3];
			rule.remote_port = args[4];
			rule.process = args[5];
			rule.policy = args[6];
			out_rules.push_back(rule); // Add rule to out_rules vector
		}
	}

	// Add default rule to out_rules to drop unspecified traffic
	rule OUT_temp;
	OUT_temp.protocol = "*";
	OUT_temp.local_ip = "*";
	OUT_temp.local_port = "*";
	OUT_temp.remote_ip = "*";
	OUT_temp.remote_port = "*";
	OUT_temp.process = "*";
	OUT_temp.policy = "DROP";
	out_rules.push_back(OUT_temp);

	// Add default rule to in_rules to drop unspecified traffic
	rule IN_temp;
	IN_temp.local_ip = "*";
	IN_temp.local_port = "*";
	IN_temp.process = "*";
	IN_temp.protocol = "*";
	IN_temp.remote_ip = "*";
	IN_temp.remote_port = "*";
	IN_temp.policy = "DROP";
	in_rules.push_back(IN_temp);

	mtx_rules.unlock(); // Unlock mutex after modifying rule tables

	cout << "DONE!" << endl << endl;
}


bool init()
{
	// Clear the console screen
	system("cls");

	cout << endl << endl;

	// Load settings and rule tables
	load();

	cout << "  OPENING SOCKET HANDLE: ";

	// Open a handle to the WinDivert driver for capturing and modifying socket traffic
	s_handle = WinDivertOpen(
		"true",                     // Capture all traffic
		WINDIVERT_LAYER_SOCKET,     // Layer for socket traffic
		1,                          // Priority (1 for high priority)
		WINDIVERT_FLAG_SNIFF + WINDIVERT_FLAG_READ_ONLY); // Flags for sniffing and read-only
	if (s_handle == INVALID_HANDLE_VALUE)
	{
		cout << "ERROR: " << GetLastError() << endl; // Print error if handle creation fails
		return false; // Indicate failure
	}

	cout << "DONE!" << endl << endl;

	cout << "  OPENING NETWORK HANDLE: ";

	// Open a handle to the WinDivert driver for capturing and modifying network traffic
	n_handle = WinDivertOpen(
		"true",                     // Capture all traffic
		WINDIVERT_LAYER_NETWORK,    // Layer for network traffic
		0,                          // Priority (0 for default priority)
		0);                         // No special flags
	if (n_handle == INVALID_HANDLE_VALUE)
	{
		cout << "ERROR: " << GetLastError() << endl; // Print error if handle creation fails
		return false; // Indicate failure
	}

	cout << "DONE!" << endl << endl;

	cout << "  DISABLING WINDOWS FIREWALL: ";

	// Disable the Windows Firewall to ensure traffic is not blocked by it
	winfw(false);

	cout << "DONE!" << endl << endl;

	cout << "  NETSTAT -A -N -O > NETSTAT.TXT: ";

	// Execute `netstat` command to capture current network connections and save to file
	system("netstat -a -n -o > netstat.txt");

	cout << "DONE!" << endl << endl;

	// Get the current time for timestamping packets
	time_t now;
	time(&now);

	cout << "  PARSING NETSTAT.TXT: ";

	unordered_map<string, string> loopback; // Store loopback connections

	// Read and parse the netstat output file
	ifstream file = ifstream("netstat.txt");
	string line;
	while (getline(file, line))
	{
		vector<string> args = split_args(line); // Split the line into arguments
		string protocol = "";
		if (args.size() > 0) protocol = args[0];
		string local_ip;
		string local_port;
		string remote_ip;
		string remote_port;
		if (protocol.compare("TCP") == 0 && args.size() == 5 ||
			protocol.compare("UDP") == 0 && args.size() == 4)
		{
			// Parse local and remote IP addresses and ports
			vector<string> local_s = split(args[1], ':');
			if (local_s.size() != 2) continue; // Skip if not valid IP/port format
			local_ip = local_s[0];
			local_port = local_s[1];

			vector<string> remote_s = split(args[2], ':');
			if (remote_s.size() != 2) continue; // Skip if not valid IP/port format
			remote_ip = remote_s[0];
			remote_port = remote_s[1];

			DWORD processId = 0;
			string state = "";
			if (protocol.compare("TCP") == 0)
			{
				state = args[3];
				processId = stoul(args[4]);
			}
			else if (protocol.compare("UDP") == 0)
			{
				processId = stoul(args[3]);
			}

			string process = processById(processId); // Get process name by ID

			// Handle different connection states
			if (state.compare("") == 0 || state.compare("LISTENING") == 0)
			{
				processByPort_[protocol + " " + local_ip + ":" + local_port] = process; // Map port to process
			}
			else
			{
				bool reject;

				// Handle loopback connections
				if (local_ip.compare(remote_ip) == 0 || ip_match(local_ip, "127.0.0.1/8")) // Loopback IP
				{
					string out_tuple = protocol + " " + local_ip + ":" + local_port + " " + remote_ip + ":" + remote_port;
					string in_tuple = protocol + " " + remote_ip + ":" + remote_port + " " + local_ip + ":" + local_port;

					if (loopback.find(in_tuple) == loopback.cend())
					{
						loopback[out_tuple] = process; // Store the outgoing connection
					}
					else // Match found for an incoming connection
					{
						string process_ = loopback[in_tuple];

						if (state.compare("ESTABLISHED") == 0 || state.compare("SYN_RECV") == 0)
						{
							if (process_loopback_packet(now, protocol,
								remote_ip, remote_port, process_,
								local_ip, local_port, process,
								0, false, true, false, false, false,
								false, &reject))
							{
								if (state.compare("ESTABLISHED") == 0)
								{
									process_loopback_packet(now, protocol,
										local_ip, local_port, process,
										remote_ip, remote_port, process_,
										0, false, true, false, false, true,
										false, &reject);
								}
							}
						}

						loopback.erase(in_tuple); // Remove the processed connection
					}
				}
				else // Handle non-loopback connections
				{
					if (state.compare("SYN_SENT") == 0)
					{
						process_packet(now, process, "->",
							protocol, local_ip, local_port, remote_ip, remote_port, 0,
							false, true, false, false, false,
							false, &reject);
					}
					else if (state.compare("SYN_RECV") == 0)
					{
						process_packet(now, process, "<-",
							protocol, local_ip, local_port, remote_ip, remote_port, 0,
							false, true, false, false, false,
							false, &reject);
					}
					else if (state.compare("ESTABLISHED") == 0)
					{
						if (process_packet(now, process, "<-",
							protocol, local_ip, local_port, remote_ip, remote_port, 0,
							false, true, false, false, false,
							false, &reject))
						{
							process_packet(now, process, "->",
								protocol, local_ip, local_port, remote_ip, remote_port, 0,
								false, true, false, false, true,
								false, &reject);
						}
						else
						{
							if (process_packet(now, process, "->",
								protocol, local_ip, local_port, remote_ip, remote_port, 0,
								false, true, false, false, false,
								false, &reject))
							{
								process_packet(now, process, "<-",
									protocol, local_ip, local_port, remote_ip, remote_port, 0,
									false, true, false, false, true,
									false, &reject);
							}
						}
					}
				}
			}
		}
	}

	cout << "DONE!" << endl << endl;

	// Initialize packet structures with default values
	PacketIpTcpInit(reset);
	reset->tcp.Rst = 1; // Set TCP RST flag
	reset->tcp.Ack = 1; // Set TCP ACK flag
	PacketIpIcmpInit(dnr);
	dnr->icmp.Type = 3;         // Destination not reachable.
	dnr->icmp.Code = 3;         // Port not reachable.
	PacketIpv6TcpInit(resetv6);
	resetv6->tcp.Rst = 1; // Set TCP RST flag
	resetv6->tcp.Ack = 1; // Set TCP ACK flag
	PacketIpv6Icmpv6Init(dnrv6);
	dnrv6->ipv6.Length = htons(sizeof(WINDIVERT_ICMPV6HDR) + 4 +
		sizeof(WINDIVERT_IPV6HDR) + sizeof(WINDIVERT_TCPHDR));
	dnrv6->icmpv6.Type = 1;     // Destination not reachable.
	dnrv6->icmpv6.Code = 4;     // Port not reachable.

	return true; // Indicate success
}


void reload()
{
	// Lock console mutex to ensure exclusive access to console operations
	mtx_console.lock();

	// Clear the console screen
	system("cls");

	cout << endl << endl;

	// Reload settings and rule tables
	load();

	cout << "  APPLYING NEW RULES: ";

	// Lock the sockets mutex to ensure exclusive access to the sockets data structure
	mtx_sockets.lock();

	// Iterate through each socket entry in the map
	for (unordered_map<string, socket_state*>::iterator i = sockets.begin(); i != sockets.end(); i++)
	{
		string tuple = i->first; // Get the tuple (key) for the socket entry
		socket_state* socket_state_ = i->second; // Get the socket state

		// Check if the socket state is for a loopback connection
		if (socket_state_->loopback)
		{
			// Handle loopback connections
			if (socket_state_->direction.compare("->") == 0) // Ensure direction is "->"
			{
				// Construct the tuple for incoming connections
				string out_tuple = tuple;
				string in_tuple = socket_state_->protocol + " " + socket_state_->remote_ip + ":" + socket_state_->remote_port + " " + socket_state_->local_ip + ":" + socket_state_->local_port;

				// Retrieve the socket states for both outgoing and incoming connections
				socket_state* out_socket = sockets[out_tuple];
				socket_state* in_socket = sockets[in_tuple];

				// Determine the action to take for this loopback socket pair
				string action = loopback_socket_action(out_socket->protocol, out_socket->local_ip, out_socket->local_port, out_socket->process, in_socket->local_ip, in_socket->local_port, in_socket->process);

				bool accept = false;
				bool hide = false;

				// Determine whether to accept or hide the socket based on the action
				if (action.compare("ACCEPT") == 0)
				{
					accept = true;
				}
				else if (action.compare("ACCEPT_HIDE") == 0)
				{
					accept = true;
					hide = true;
				}

				// If accepted, manage the order and visibility of the sockets
				if (accept)
				{
					list<string>::iterator it;
					if (hide)
					{
						// Remove from order list if hiding
						it = find(sockets_order.begin(), sockets_order.end(), out_tuple);
						if (it != sockets_order.end())
						{
							it = sockets_order.erase(it);
						}

						it = find(sockets_order.begin(), sockets_order.end(), in_tuple);
						if (it != sockets_order.end())
						{
							it = sockets_order.erase(it);
						}
					}
					else
					{
						// Add to the front of the order list if accepting
						it = find(sockets_order.begin(), sockets_order.end(), out_tuple);
						if (it == sockets_order.end())
						{
							sockets_order.push_front(out_tuple);
						}
						it = find(sockets_order.begin(), sockets_order.end(), in_tuple);
						if (it == sockets_order.end())
						{
							sockets_order.push_front(in_tuple);
						}
					}
				}
				else
				{
					// Remove sockets from the map and order list if not accepted
					sockets.erase(out_tuple);
					sockets_order.remove(out_tuple);

					sockets.erase(in_tuple);
					sockets_order.remove(in_tuple);
				}
			}
		}
		else
		{
			// Handle non-loopback connections
			string action = socket_action(socket_state_->process, socket_state_->direction, socket_state_->protocol, socket_state_->local_ip, socket_state_->local_port, socket_state_->remote_ip, socket_state_->remote_port);

			bool accept = false;
			bool hide = false;

			// Determine whether to accept or hide the socket based on the action
			if (action.compare("ACCEPT") == 0)
			{
				accept = true;
			}
			else if (action.compare("ACCEPT_HIDE") == 0)
			{
				accept = true;
				hide = true;
			}

			// If accepted, manage the order and visibility of the sockets
			if (accept)
			{
				if (hide)
				{
					// Remove from order list if hiding
					list<string>::iterator it = find(sockets_order.begin(), sockets_order.end(), tuple);
					if (it != sockets_order.end())
					{
						it = sockets_order.erase(it);
					}
				}
				else
				{
					// Add to the front of the order list if accepting
					list<string>::iterator it = find(sockets_order.begin(), sockets_order.end(), tuple);
					if (it == sockets_order.end())
					{
						sockets_order.push_front(tuple);
					}
				}
			}
			else
			{
				// Remove socket from the map and order list if not accepted
				sockets.erase(tuple);
				sockets_order.remove(tuple);
			}
		}
	}

	// Unlock the sockets mutex
	mtx_sockets.unlock();

	cout << "DONE!" << endl << endl;

	// Unlock the console mutex
	mtx_console.unlock();
}


void socket_()
{
	// Continuously process socket events
	for (ULONG i = 0; ; i++)
	{
		WINDIVERT_ADDRESS addr;

		// Receive a packet or continue if there's an error or the packet is IPv6
		if (!WinDivertRecv(s_handle, NULL, 0, NULL, &addr)) continue;
		if (addr.IPv6) continue;

		// Lock the mutex for managing the queue
		mtx_queued.lock();

		time_t now;
		time(&now); // Get the current time

		// Retrieve the process name by its ID
		string process = processById(addr.Socket.ProcessId);

		// Determine the type of socket event
		string event;
		switch (addr.Event)
		{
		case WINDIVERT_EVENT_SOCKET_BIND:
			event = "BIND";
			break;
		case WINDIVERT_EVENT_SOCKET_LISTEN:
			event = "LISTEN";
			break;
		case WINDIVERT_EVENT_SOCKET_CONNECT:
			event = "CONNECT";
			break;
		case WINDIVERT_EVENT_SOCKET_ACCEPT:
			event = "ACCEPT";
			break;
		case WINDIVERT_EVENT_SOCKET_CLOSE:
			event = "CLOSE";
			break;
		default:
			event = "";
			break;
		}

		// Determine the protocol used by the socket
		string protocol;
		switch (addr.Socket.Protocol)
		{
		case IPPROTO_TCP:
			protocol = "TCP";
			break;
		case IPPROTO_UDP:
			protocol = "UDP";
			break;
		case IPPROTO_ICMP:
			protocol = "ICMP";
			break;
		case IPPROTO_ICMPV6:
			protocol = "ICMPV6";
			break;
		default:
			protocol = to_string(addr.Socket.Protocol);
			break;
		}

		// Determine the direction of the socket event
		string direction;
		if (addr.Outbound)
			direction = "->"; // Outbound
		else
			direction = "<-"; // Inbound

		// Convert IP addresses to string format
		char local_str[INET6_ADDRSTRLEN + 1], remote_str[INET6_ADDRSTRLEN + 1];
		WinDivertHelperFormatIPv6Address(addr.Socket.LocalAddr, local_str, sizeof(local_str));
		WinDivertHelperFormatIPv6Address(addr.Socket.RemoteAddr, remote_str, sizeof(remote_str));

		string local_ip = string(local_str);
		if (local_ip.compare("::") == 0) local_ip = "0.0.0.0"; // Convert "::" to "0.0.0.0"
		string local_port = to_string(addr.Socket.LocalPort);

		string remote_ip = string(remote_str);
		if (remote_ip.compare("::") == 0) remote_ip = "0.0.0.0"; // Convert "::" to "0.0.0.0"
		string remote_port = to_string(addr.Socket.RemotePort);

		// (Optional) Log the socket event
		// log_(now, protocol, direction, local_ip, local_port, remote_ip, remote_port, process, event);

		// Update the processByPort map based on the event
		if (event.compare("BIND") == 0 || (addr.Loopback && event.compare("CONNECT") == 0))
		{
			// Add or update the entry in the processByPort map
			mtx_processByPort.lock();
			processByPort_[protocol + " " + local_ip + ":" + local_port] = process;
			mtx_processByPort.unlock();
		}
		else if (event.compare("CLOSE") == 0 && remote_ip.compare("0.0.0.0") == 0 && remote_port.compare("0") == 0)
		{
			// Remove the entry from the processByPort map if the socket is closed
			mtx_processByPort.lock();
			processByPort_.erase(protocol + " " + local_ip + ":" + local_port);
			mtx_processByPort.unlock();
		}

		// Unlock the mutex after processing
		mtx_queued.unlock();
	}
}


void network()
{
	// Define the packet address and buffer for received packets
	WINDIVERT_ADDRESS addr, addr_; // Address structure for the packet
	char packet[MAXBUF];    // Buffer to hold the received packet data
	UINT packet_len;        // Length of the received packet

	// Define pointers for various headers in the packet
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ipv6_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmpv6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;
	char src_str[INET6_ADDRSTRLEN + 1], dst_str[INET6_ADDRSTRLEN + 1]; // Buffers for source and destination IP addresses
	PVOID payload;       // Pointer to the packet payload
	UINT payload_len;    // Length of the payload

	// Define variables for packet details
	string protocol;     // Protocol type (TCP, UDP, etc.)
	string src_ip, dst_ip; // Source and destination IP addresses
	bool fin, syn, rst, psh, ack; // TCP flags
	string direction;    // Packet direction (inbound or outbound)
	string src_port, dst_port; // Source and destination ports

	time_t now; // Variable to store the current time

	// Infinite loop to continuously process incoming packets
	for (ULONG i = 0; ; i++)
	{
		// Receive a packet; if failed, continue to the next iteration
		if (!WinDivertRecv(n_handle, packet, sizeof(packet), &packet_len, &addr)) continue;

		// Lock the mutex to safely access shared resources
		mtx_queued.lock();

		// Get the current time
		time(&now);

		// Parse the received packet into various headers and payload
		WinDivertHelperParsePacket(packet, packet_len, &ip_header, &ipv6_header,
			NULL, &icmp_header, &icmpv6_header, &tcp_header, &udp_header, &payload,
			&payload_len, NULL, NULL);

		// Check if valid IP and TCP/UDP headers are present; if not, skip processing
		if (ip_header == NULL || (tcp_header == NULL && udp_header == NULL))
		{
			goto cont; // Skip to the end of the current iteration
		}

		// Convert IP addresses from binary format to string format
		WinDivertHelperFormatIPv4Address(ntohl(ip_header->SrcAddr), src_str, sizeof(src_str));
		WinDivertHelperFormatIPv4Address(ntohl(ip_header->DstAddr), dst_str, sizeof(dst_str));

		src_ip = string(src_str); // Source IP address as string
		dst_ip = string(dst_str); // Destination IP address as string

		// Initialize TCP flags
		fin = false;
		syn = false;
		rst = false;
		psh = false;
		ack = false;

		// Determine protocol type and extract port numbers and flags
		if (tcp_header != NULL)
		{
			protocol = "TCP"; // Protocol is TCP
			src_port = to_string(ntohs(tcp_header->SrcPort)); // Source port number
			dst_port = to_string(ntohs(tcp_header->DstPort)); // Destination port number

			// Extract TCP flags
			fin = tcp_header->Fin;
			syn = tcp_header->Syn;
			rst = tcp_header->Rst;
			psh = tcp_header->Psh;
			ack = tcp_header->Ack;
		}

		if (udp_header != NULL)
		{
			protocol = "UDP"; // Protocol is UDP
			src_port = to_string(ntohs(udp_header->SrcPort)); // Source port number
			dst_port = to_string(ntohs(udp_header->DstPort)); // Destination port number
		}

		bool accept; // Flag to indicate if the packet is accepted
		bool reject; // Flag to indicate if the packet is rejected

		// Process packets based on whether they are loopback or outbound
		if (addr.Loopback)
		{
			// Handle loopback packets
			accept =
				process_loopback_packet(now, protocol,
					src_ip, src_port, processByPort(protocol, src_ip, src_port),
					dst_ip, dst_port, processByPort(protocol, dst_ip, dst_port),
					packet_len, fin, syn, rst, psh, ack, true, &reject);
		}
		else if (addr.Outbound)
		{
			// Handle outbound packets
			accept =
				process_packet(now, processByPort(protocol, src_ip, src_port), "->",
					protocol, src_ip, src_port, dst_ip, dst_port,
					packet_len, fin, syn, rst, psh, ack, true, &reject);
		}
		else
		{
			// Handle inbound packets
			accept =
				process_packet(now, processByPort(protocol, dst_ip, dst_port), "<-",
					protocol, dst_ip, dst_port, src_ip, src_port,
					packet_len, fin, syn, rst, psh, ack, true, &reject);
		}

		// Send the packet if it is accepted
		if (accept)
			WinDivertSend(n_handle, packet, packet_len, NULL, &addr);

		// Handle packet rejection
		if (reject)
		{
			if (tcp_header != NULL)
			{
				// Construct and send a TCP reset packet
				reset->ip.SrcAddr = ip_header->DstAddr;
				reset->ip.DstAddr = ip_header->SrcAddr;
				reset->tcp.SrcPort = tcp_header->DstPort;
				reset->tcp.DstPort = tcp_header->SrcPort;
				reset->tcp.SeqNum =
					(tcp_header->Ack ? tcp_header->AckNum : 0); // Set sequence number
				reset->tcp.AckNum =
					(tcp_header->Syn ?
						htonl(ntohl(tcp_header->SeqNum) + 1) :
						htonl(ntohl(tcp_header->SeqNum) + payload_len)); // Set acknowledgment number

				memcpy(&addr_, &addr, sizeof(addr_));
				addr_.Outbound = !addr.Outbound; // Reverse the direction
				WinDivertHelperCalcChecksums((PVOID)reset, sizeof(TCPPACKET), &addr_, 0); // Calculate checksums
				WinDivertSend(n_handle, (PVOID)reset, sizeof(TCPPACKET), NULL, &addr_); // Send the reset packet
			}
			else if (udp_header != NULL)
			{
				// Construct and send an ICMP packet for UDP rejection
				UINT icmp_length = ip_header->HdrLength * sizeof(UINT32) + 8; // Length of the ICMP packet
				memcpy(dnr->data, ip_header, icmp_length); // Copy IP header
				icmp_length += sizeof(ICMPPACKET); // Add ICMP packet size
				dnr->ip.Length = htons((UINT16)icmp_length); // Set IP header length
				dnr->ip.SrcAddr = ip_header->DstAddr;
				dnr->ip.DstAddr = ip_header->SrcAddr;

				memcpy(&addr_, &addr, sizeof(addr_));
				addr_.Outbound = !addr.Outbound; // Reverse the direction
				WinDivertHelperCalcChecksums((PVOID)dnr, icmp_length, &addr_, 0); // Calculate checksums
				WinDivertSend(n_handle, (PVOID)dnr, icmp_length, NULL, &addr_); // Send the ICMP packet
			}
		}

	cont:
		// Unlock the mutex after processing the packet
		mtx_queued.unlock();
	}
}



void heartbeat()
{
	// Infinite loop to continuously check and update socket states
	for (;;)
	{
		// Lock the mutex to safely access and modify the sockets map and order list
		mtx_sockets.lock();

		time_t now; // Variable to store the current time
		time(&now); // Get the current time

		// Iterate over the sockets map
		for (unordered_map<string, socket_state*>::iterator i = sockets.begin(); i != sockets.end(); )
		{
			// Extract the tuple (key) and the socket state (value) from the map
			string tuple = i->first;
			socket_state* socket_state_ = i->second;

			// Check if the socket's status is not "EST" (established) and if the timeout period has elapsed
			if (socket_state_->status.compare("EST") != 0 &&
				difftime(now, socket_state_->heartbeat) >= TIMEOUT)
			{
				// Remove the socket from the order list and the map
				sockets_order.remove(tuple);
				i = sockets.erase(i); // Erase the current iterator and move to the next
				delete socket_state_; // Delete the socket state object to free memory
				continue; // Continue to the next iteration of the loop
			}

			// If the socket status is not "TOUT" (timeout)
			if (socket_state_->status.compare("TOUT") != 0)
			{
				// Check if the socket's protocol and timeout conditions are met
				if (socket_state_->protocol.compare("UDP") == 0 && difftime(now, socket_state_->heartbeat) >= UDP_TIMEOUT ||
					socket_state_->protocol.compare("TCP") == 0 && difftime(now, socket_state_->heartbeat) >= TCP_TIMEOUT)
				{
					// Update the socket status to "TOUT" (timeout) and reset the heartbeat time
					socket_state_->status = "TOUT";
					socket_state_->heartbeat = now;
				}
			}

			i++; // Move to the next iterator in the map
		}

		// Unlock the mutex to allow other threads to access the sockets map and order list
		mtx_sockets.unlock();

		// Sleep for 1 second before the next iteration of the loop
		this_thread::sleep_for(chrono::seconds(1));
	}
}


void activestat()
{
	// Infinite loop to continuously refresh and display socket status
	for (; ; )
	{
		// Check if the application is in mode 0 and not paused
		if (mode == 0 && !paused)
		{
			// Lock the mutex to safely access console and socket information
			mtx_console.lock();

			time_t now; // Variable to store the current time
			time(&now); // Get the current time

			// Check if the refresh interval has passed
			if (difftime(now, activestat_heartbeat) >= REFRESH_INTERVAL)
			{
				// Lock the mutex to safely access and modify the sockets map
				mtx_sockets.lock();

				// Clear the console screen
				system("cls");

				CONSOLE_SCREEN_BUFFER_INFO csbi; // Console screen buffer info
				GetConsoleScreenBufferInfo(console, &csbi); // Retrieve console screen buffer info
				short rows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1; // Calculate the number of rows in the console window
				short columns = csbi.srWindow.Right - csbi.srWindow.Left + 1; // Calculate the number of columns in the console window

				// Set text color to red (31)
				SetConsoleTextAttribute(console, 31);

				// Placeholder for the header row that will be printed (commented out)
				// cout << left
				//      << setw((streamsize)columns - 1) << "PRO STAT LOCAL                  REMOTE                RECV SENT IDL PROCESS" << endl
				//      << right;

				size_t row = 0; // Initialize row counter

				// Iterate over the list of socket tuples in order
				for (list<string>::iterator i = sockets_order.begin(); i != sockets_order.end(); i++)
				{
					// Break the loop if there is not enough space to display more rows
					if (row + 2 == (size_t)rows)
						break;

					string& tuple = *i; // Get the current tuple (key)
					socket_state* socket_state_ = sockets[tuple]; // Get the corresponding socket state

					// Calculate the idle time
					ULONG idle = difftime(now, socket_state_->heartbeat);
					string idle_ = idle > 999 ? "000" : to_string(idle); // Format idle time

					// Set console text color based on socket status
					if (socket_state_->status.compare("CNCT") == 0)
						SetConsoleTextAttribute(console, 14); // Yellow for "CNCT"
					else if (socket_state_->status.compare("EST") == 0)
						SetConsoleTextAttribute(console, 10); // Green for "EST"
					else
						SetConsoleTextAttribute(console, 9);  // Blue for other statuses

					// Placeholder for printing socket state information (commented out)
					// cout << left
					//      << socket_state_->protocol << " "
					//      << setw(4) << socket_state_->status << " "
					//      << right
					//      << format_ip(socket_state_->local_ip) << ":" << setw(5) << socket_state_->local_port
					//      << socket_state_->direction
					//      << format_ip(socket_state_->remote_ip) << ":" << setw(5) << socket_state_->remote_port << " "
					//      << setw(4) << format(socket_state_->bytes_in) << " "
					//      << setw(4) << format(socket_state_->bytes_out) << " "
					//      << setw(3) << idle_ << " "
					//      << left
					//      << setw((streamsize)columns - 69) << truncate(socket_state_->process, (streamsize)columns - 69)
					//      << right
					//      << endl;

					row++; // Move to the next row
				}

				// Print empty lines if there is space left in the console
				for (; row + 2 < (size_t)rows; row++)
				{
					// cout << endl; // Placeholder for printing empty lines (commented out)
				}

				// Set text color to red again (31)
				SetConsoleTextAttribute(console, 31);

				// Placeholder for the footer row with controls (commented out)
				// cout << "RE[L]OAD   [R]EFRESH: [-] " << setw(2) << REFRESH_INTERVAL << "s [+]   [P]AUSE   LO[G]   LEGEN[D]   [Q]UIT" << setw((streamsize)columns - 72) << " ";

				// Unlock the mutex to allow other threads to access the sockets map
				mtx_sockets.unlock();

				// Update the last heartbeat time
				activestat_heartbeat = now;

				// Set text color back to default (15)
				SetConsoleTextAttribute(console, 15);
			}

			// Unlock the mutex to allow other threads to access the console
			mtx_console.unlock();
		}

		// Sleep for 1 second before the next refresh
		this_thread::sleep_for(chrono::seconds(1));
	}
}


void legend()
{
	// Lock the mutex to safely access and modify the console
	mtx_console.lock();

	// Clear the console screen
	system("cls");

	// Set console text color to white (15) for general text
	SetConsoleTextAttribute(console, 15);
	// Print the title for the legend (commented out)
	// cout << "  LEGEND:" << endl << endl;

	// Set console text color to white (15) for section titles
	SetConsoleTextAttribute(console, 15);
	// Print the section title for "ACTIVE STAT" (commented out)
	// cout << "    ACTIVE STAT:" << endl << endl;

	// Set console text color to yellow (14) for "Connecting" status
	SetConsoleTextAttribute(console, 14);
	// Print the description for "CNCT: Connecting" status (commented out)
	// cout << "      CNCT: Connecting" << endl << endl;

	// Set console text color to green (10) for "Established" status
	SetConsoleTextAttribute(console, 10);
	// Print the description for "EST: Established" status (commented out)
	// cout << "      EST : Established" << endl << endl;

	// Set console text color to blue (9) for other statuses
	SetConsoleTextAttribute(console, 9);
	// Print descriptions for additional statuses (commented out)
	// cout << "      LFIN: FIN Sent" << endl;
	// cout << "      RFIN: FIN Received" << endl;
	// cout << "      CLSD: Closed" << endl;
	// cout << "      LRST: RST Sent" << endl;
	// cout << "      RRST: RST Received" << endl;
	// cout << "      TOUT: Inactivity Time-out" << endl << endl;

	// Set console text color back to white (15) for section titles
	SetConsoleTextAttribute(console, 15);
	// Print the section title for "LOGGING" (commented out)
	// cout << "    LOGGING:" << endl << endl;

	// Set console text color to green (10) for accepted log entries
	SetConsoleTextAttribute(console, 10);
	// Print the description for "ACCEPTED" log entries (commented out)
	// cout << "      ACCEPTED" << endl << endl;

	// Set console text color to red (12) for dropped log entries
	SetConsoleTextAttribute(console, 12);
	// Print the description for "DROPPED" log entries (commented out)
	// cout << "      DROPPED" << endl << endl;

	// Set console text color back to white (15) for general instructions
	SetConsoleTextAttribute(console, 15);
	// Print instruction to press [D] to return (commented out)
	// cout << "  PRESS [D] AGAIN TO RETURN" << endl << endl;

	// Unlock the mutex to allow other threads to access the console
	mtx_console.unlock();

	// Wait for the user to press the 'D' key to exit the legend view
	while (toupper(_getch()) != 'D');
}


void quit()
{
	// Lock the mutex to safely access and modify the console
	mtx_console.lock();

	// Clear the console screen
	system("cls");

	// Set console text color to white (15) for general text (commented out)
	// SetConsoleTextAttribute(console, 15);

	// Print an empty line for spacing (commented out)
	// cout << endl << endl;

	// Print a message indicating that Windows Firewall is being re-enabled (commented out)
	// cout << "  RE-ENABLING WINDOWS FIREWALL: ";

	// Call the function to re-enable Windows Firewall
	winfw(true);

	// Print a completion message (commented out)
	// cout << "DONE!" << endl << endl;

	// Unlock the mutex to allow other threads to access the console
	mtx_console.unlock();
}



BOOL WINAPI CtrlHandler(DWORD fdwCtrlType)
{
	// Handle different types of control events
	switch (fdwCtrlType)
	{
	case CTRL_C_EVENT:  // Ctrl+C was pressed
	case CTRL_CLOSE_EVENT:  // The console window is being closed
	case CTRL_BREAK_EVENT:  // Ctrl+Break was pressed
	case CTRL_LOGOFF_EVENT:  // The user is logging off
	case CTRL_SHUTDOWN_EVENT:  // The system is shutting down
		// Call the quit function to perform cleanup operations
		quit();
		// Return FALSE to allow the system to handle the event
		return FALSE;

	default:
		// For other control events, return FALSE to allow the system to handle them normally
		return FALSE;
	}
}


int main()
{
	// Set the console control handler to handle Ctrl+C, Ctrl+Break, and other console events.
	SetConsoleCtrlHandler(CtrlHandler, TRUE);

	// Get a handle to the console's output buffer.
	console = GetStdHandle(STD_OUTPUT_HANDLE);

	// Initialize the program; if initialization fails, return 1 to indicate an error.
	if (!init()) return 1;

	// Start threads for handling socket events, network packets, heartbeat checking, and active status display.
	thread _socket(socket_);
	thread _network(network);
	thread _heartbeat(heartbeat);
	thread _activestat(activestat);

	// Console screen buffer information structure.
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	short rows, columns;

	// Main loop for processing user commands.
	for (; ; )
	{
		// Get the user's input and convert it to uppercase.
		int c = toupper(_getch());
		switch (c)
		{
		case 'L':
			// Reload the configuration and reset the heartbeat for active status display.
			reload();
			activestat_heartbeat = 0;
			break;

		case '+':
			// Increase the refresh interval for the active status display.
			switch (REFRESH_INTERVAL)
			{
			case 1:
				REFRESH_INTERVAL = 5;
				break;
			case 5:
				REFRESH_INTERVAL = 15;
				break;
			case 15:
				REFRESH_INTERVAL = 60;
				break;
			case 60:
				break;
			}
			activestat_heartbeat = 0;
			break;

		case '-':
			// Decrease the refresh interval for the active status display.
			switch (REFRESH_INTERVAL)
			{
			case 1:
				break;
			case 5:
				REFRESH_INTERVAL = 1;
				break;
			case 15:
				REFRESH_INTERVAL = 5;
				break;
			case 60:
				REFRESH_INTERVAL = 15;
				break;
			}
			activestat_heartbeat = 0;
			break;

		case 'R':
			// Reset the heartbeat for the active status display to force a refresh.
			activestat_heartbeat = 0;
			break;

		case 'P':
			// Pause the active status display and wait for the user to press 'P' again to continue.
			paused = true;

			mtx_console.lock();

			GetConsoleScreenBufferInfo(console, &csbi);
			rows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
			columns = csbi.srWindow.Right - csbi.srWindow.Left + 1;

			SetConsoleTextAttribute(console, 31);
			// Display a pause message in the console.
			//cout << "\r" << left << setw((streamsize)columns - 1) << "PAUSED: PRESS [P] AGAIN TO CONTINUE" << right;
			SetConsoleTextAttribute(console, 15);

			mtx_console.unlock();

			// Wait for the user to press 'P' again to resume.
			while (toupper(_getch()) != 'P');

			activestat_heartbeat = 0;

			paused = false;

			break;

		case 'G':
			// Enter logging mode and wait for the user to press 'G' again to return.
			mode = 1;

			mtx_console.lock();

			system("cls");

			GetConsoleScreenBufferInfo(console, &csbi);
			rows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
			columns = csbi.srWindow.Right - csbi.srWindow.Left + 1;

			SetConsoleTextAttribute(console, 31);
			// Display a logging message in the console.
			//cout << left << setw((streamsize)columns - 1) << "LOGGING: PRESS [G] AGAIN TO RETURN" << endl << right;
			SetConsoleTextAttribute(console, 15);

			mtx_console.unlock();

			// Wait for the user to press 'G' again to return to the previous mode.
			while (toupper(_getch()) != 'G');

			activestat_heartbeat = 0;

			mode = 0;

			break;

		case 'D':
			// Display the legend and wait for the user to press 'D' again to return.
			mode = -1;

			legend();

			activestat_heartbeat = 0;

			mode = 0;

			break;

		case 'Q':
			// Quit the application and perform cleanup.
			quit();

			// Exit the main loop and program.
			goto exit;

		}
	}

exit:
	// Exit the program with a status code of 0, indicating successful termination.
	exit(0);
}
