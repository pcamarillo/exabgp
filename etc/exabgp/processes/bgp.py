#!/usr/bin/env python

""" ExaBGP based Route Server """
""" January 2014 """
""" Pablo Camarillo - IMDEA Networks, Madrid """

import sys 			#To read from stdin+exit+others
import os 			#Environment variables os.environ // 
import time			#Keep track of the time -> Convergence time
import syslog		#To save on linux log messages received + sent (cat /var/log/syslog|grep RIB)
import threading	#To implement async IO
import Queue 		#To send JSON messages from one thread to another
import json 		#To interpratate the JSON received msgs
import struct 		#Optimize memory usage when saving IPs
import re 			#Parse regex expressions
import random 		#To fill in the peering table

class RIB(threading.Thread):
	#Loc-RIB
	rib = []

	#Neighbor list
	neighbors = []

	#Clocks
	t1 = 0;
	t2 = 0;
	Tdelta = 200;

	def __init__(self, q, peers_number):
		self.q = q
		#Peering table. Initialize it randomly
		self.peering = [[(random.random() < 0.95) for i in range(peers_number) ] for j in range(peers_number)]

		#Attributes cache
		self.attributes_cache = []

		#Initialize neighbors list
		#This should be in the best practise's book for route servers...(ironic)
		for i in range(1, peers_number+1):
			self.neighbors.append('10.0.0.' + str(i))
			
		threading.Thread.__init__(self)
		if 'rib.LOG' in os.environ:
			syslog.openlog("RIB")
			syslog.syslog(syslog.LOG_ALERT, 'ExaBGP Route Server RIB process started')

		self.t1 = time.time()
    
	def filtering(self, route_router_id, peer_to_check_id):
		#If they are the same return False. Don't send updates for himself.
		if route_router_id == peer_to_check_id:
			return False
		ip1 = route_router_id.split('.')
		ip1 = map(int, ip1)
		ip2 = peer_to_check_id.split('.')
		ip2 = map(int, ip2)
		
		#If A wants to receive updates from B, and biceversa, return True
		if self.peering[ip1[3]-1][ip2[3]-1] and self.peering[ip2[3]-1][ip1[3]-1]:
			return True
		else:
			return False

	def run(self):
		if 'rib.LOG' in os.environ:
			syslog.syslog(syslog.LOG_ALERT, 'ExaBGP RS waiting for updates...')
		self.t2 = time.time()
		#Receive messages. Update Loc-RIB. Send updates to Adj-RIB-Out
		while int(time.time())-int(self.t2)<self.Tdelta:
			if 'rib.LOG' in os.environ:
				syslog.syslog(syslog.LOG_ALERT, 'Timers are ' + str(time.time()) + ' - ' + str(self.t2))

			try:
				message = self.q.get(True, 5) #True indicates that it is a blocking call. [If queue is empty this call will wait until there's something]
			except Queue.Empty:
				if time.time()-self.t2 >= self.Tdelta:
					syslog.syslog(syslog.LOG_ALERT, 'Timer expired')
					break
				else:
					syslog.syslog(syslog.LOG_ALERT, 'Still working there...')
					continue
			data = json.loads(message)
			self.t2 = time.time()	#Set second timer
			if 'rib.LOG' in os.environ:
				syslog.syslog(syslog.LOG_ALERT, str(data))

			if 'update' in data['neighbor']:
				#Message received was an update

				#--------------------------------------------------------------
				# { 
				# 	"exabgp": "3.3.0", 
				# 	"time": 1389135454, 
				# 	"neighbor": { 
				# 		"ip": "10.0.0.1", 
				# 		"update": { 
				# 			"attribute": { 
				# 				"origin": "igp", 
				# 				"as-path": [ 65001 ], 
				# 				"atomic-aggregate": false 
				# 			}, 
				# 			"announce": { 
				# 				"10.0.0.1" : { 
				# 					"10.1.1.0/24": {  } 
				# 				} 
				# 			} 
				# 		} 
				# 	} 
				# }
				#--------------------------------------------------------------

				#Means an update for a new route adding was received
				if 'attribute' in data['neighbor']['update']:
					if not '3.3.0' in data['exabgp']:
						#We received an update for different exabgp version. Discard it.
						if 'rib.LOG' in os.environ:
							syslog.syslog(syslog.WARNING_ALERT, 'Another version of ExaBGP received. Discarding it')
						continue #Iterates the while receiving loop

					if 'rib.LOG' in os.environ:
						syslog.syslog(syslog.LOG_ALERT, 'Regular update(add) received. Parsing it.')

					#If still here means a new route was received
					attr = None
					rib_entry = None
					#We check if those attributes previously existed
					for x in self.attributes_cache:
						if x.isEqual(data['neighbor']):
							attr = x
							break
					#Means not attributes were found...therefore..we have to create them		
					if not attr:
						attr = Attributes(data['neighbor'])
						#We also add them to the attributes cache
						self.attributes_cache.append(attr)

					if 'rib.LOG' in os.environ:
						syslog.syslog(syslog.LOG_ALERT, 'Attributes processed')

					#Now we go per route in json received
					for next_hop in data['neighbor']['update']['announce'].keys():
						for prefix in data['neighbor']['update']['announce'][next_hop].keys():
							#Traverse the rib entries we have looking whether any matches (with same attr and next_hop)
							for x in self.rib:
								if x.check_validity(attr, next_hop):
									rib_entry = x
									break
							#If no entry was found...therefore we must create it
							if not rib_entry:
								rib_entry = RIB_entry(attr, next_hop)
								self.rib.append(rib_entry)
							#Now that we have the rib entry in case that it wasn't there...append to it the route
							if prefix not in rib_entry.prefixes:
								rib_entry.add_route(prefix)
								if 'rib.LOG' in os.environ:
									syslog.syslog(syslog.LOG_ALERT, 'Route added to RIB')
								#Route is added to the rib...now we have to announce it
								#Add them to neighbor's Adj-LOC-Out by sending control message
								control_msg = ''
								for x in self.neighbors:
									if self.filtering(ip_from_memory(attr.ip), x):
										#Fix for the first element
										if control_msg != '':
											control_msg += ', '
										control_msg += 'neighbor ' + x + ' '
								#If there is any neighbor that matches the update....
								if control_msg != '':
									control_msg_to_send = control_msg + 'announce route ' + prefix + ' next-hop ' + ip_from_memory(rib_entry.next_hop) + str(attr) 
									print(control_msg_to_send)
									if 'rib.LOG' in os.environ:
										syslog.syslog(syslog.LOG_ALERT, control_msg_to_send)

				#A new route withdraw was received
				if 'withdraw' in data['neighbor']['update'].keys():
					if not 'ipv4 unicast' in data['neighbor']['update']['withdraw'].keys():
						#We received an update for something different than a regular route. Discard it.
						if 'rib.LOG' in os.environ:
							syslog.syslog(syslog.LOG_ALERT, 'Funky update(withdrawn) received. Discarding it')
						continue #Iterates the while receiving loop

					if 'rib.LOG' in os.environ:
						syslog.syslog(syslog.LOG_ALERT, 'Regular update(withdraw) received. Parsing it.')
					#Means we received a withdraw for a route
					update_neighbor = data['neighbor']['ip'] #Neighbor from which take away route
					routes_to_withdrawn = data['neighbor']['update']['withdraw']['ipv4 unicast'].keys() #routes_to_withdrawn is an array with the routes to screw

					#Delete them from Loc-RIB
					for x in self.rib:
						if update_neighbor == ip_from_memory(x.attributes.ip):
							#Means we found it...
							for y in routes_to_withdrawn:
								if x.del_route(y):
									#Route was deleted and rib entry now is empty.
									self.rib.remove(x)
									routes_to_withdrawn.remove(y)
							if routes_to_withdrawn.count() == 0:
								#Done with all routes....
								break
								#(If we are not done we will keep looking for other rib entries with different attributes, but same neighbor that matches)
						
					#Delete them from neighbor's Adj-LOC-Out
					control_msg = ''
					for x in self.neighbors:
						#We sent a control msg to all the other neighbors to withdrawn the route
						if filtering(update_neighbor, x):
							#Fix for the first element
							if not control_msg:
								control_msg += ', '
							control_msg += 'neighbor ' + x + ' '
					#If there is any neighbor => If there is more than one neighbor in the RIB
					if control_msg != "":
						routes_to_withdrawn = data['neighbor']['update']['withdraw']['ipv4 unicast']
						for x in routes_to_withdrawn:
							control_msg_to_send = control_msg + 'withdraw route ' + x + ' next-hop ' + update_neighbor 
							print(control_msg_to_send)
							if 'rib.LOG' in os.environ:
								syslog.syslog(syslog.LOG_ALERT, control_msg_to_send)

			if 'notification' in data:
				if data['notification'] == 'shutdown':
					#Shutdown was received...
					#Force destroying the variables
					rib = []
					neighbors = []
					attributes_cache = []
					exit(0)

			if 'rib.LOG' in os.environ:
				syslog.syslog('Route processed correctly... ')


		#Define what to do if timer has expired
		if 'rib.LOG' in os.environ:
			syslog.syslog(syslog.LOG_ALERT, 'Convergence time was ' + str("%.3f" % (self.t2-self.t1)) + ' seconds')
		
		#Write to file...
		saveResults("%.3f" % (self.t2-self.t1), len(self.neighbors))

		if 'rib.LOG' in os.environ:
			syslog.syslog(syslog.LOG_ALERT, 'Results saved. Performing shutdown.')
		print('shutdown')
		sleep(2)
		os.system('/root/restart.script')
		exit()
	
class Attributes:
	#Will be saved as a string. Using struct pack of 4*uint8_t
	ip = None
	#Will be saved as a string. Using struct pack of uint16_t
	as_path = None
	communities = None
	multi_exit_disc = None
	#Will be saved as boolean. IGP=False, EGP=True, if != then save string
	origin = None

	def __init__(self, rawdata = None):
		self.ip = ip_from_string(rawdata['ip'])
		if 'as-path' in rawdata['update']['attribute']:
			length = len(rawdata['update']['attribute']['as-path'])
			self.as_path = struct.pack(length*'H', *rawdata['update']['attribute']['as-path'])
		if 'communities' in rawdata['update']['attribute']:
			self.communities = rawdata['update']['attribute']['communities']
		if 'multi-exit-disc' in rawdata['update']['attribute']:
			self.multi_exit_disc = rawdata['update']['attribute']['multi-exit-disc']
		if 'origin' in rawdata['update']['attribute']:
			if rawdata['update']['attribute']['origin'] == 'igp':
				self.origin = False
			elif rawdata['update']['attribute']['origin'] == 'egp':
				self.origin = True
			else:
				self.origin = rawdata['update']['attribute']['origin']	

	def __str__(self):
		#WARNING: Remains to be added the ip of the neighbor from which the update was received from
		attr = ''
		if self.as_path:
			length = len(self.as_path)/2
			x = []
			x[0:length] = struct.unpack(length*'H', self.as_path)
			attr += (' as-path ' + str(x))
		if self.communities:
			attr += (' communities ' + str(self.communities))
		if self.multi_exit_disc:
			attr += (' multi-exit-disc ' + str(self.multi_exit_disc))
		if self.origin:
			if self.origin == False:
				attr += ' origin igp'
			elif self.origin == True:
				attr += ' origin egp'
			else:
				attr += (' origin ' + str(self.origin))
		return attr;

	def isEqual(self, rawdata):
		#If there is any different attribute from those passed as parameter...
		if not self.ip == ip_from_string(rawdata['ip']):
			return False
		if 'as-path' in rawdata['update']['attribute']:
			length = len(rawdata['update']['attribute']['as-path'])
			received_as_path = struct.pack(length*'H', *rawdata['update']['attribute']['as-path'])
			if self.as_path != received_as_path:
				return False
		if 'communities' in rawdata['update']['attribute']:
			if self.communities != rawdata['update']['attribute']['communities']:
				return False
		if 'multi-exit-disc' in rawdata['update']['attribute']:
			if self.multi_exit_disc != rawdata['update']['attribute']['multi-exit-disc']:
				return False
		if 'origin' in rawdata['update']['attribute']:
			if rawdata['update']['attribute']['origin'] == 'igp':
				boole = False
			elif rawdata['update']['attribute']['origin'] == 'egp':
				boole = True
			else:
				boole = rawdata['update']['attribute']['origin']
			if self.origin != boole:
				return False
		return True


class RIB_entry:
	attributes = None
	next_hop = None
	prefixes = []

	def __init__(self, attributes, next_hop):
		self.attributes = attributes
		self.next_hop = ip_from_string(next_hop)

	def add_route(self, prefix):
		self.prefixes.append(ip_from_string(prefix, True))

	def del_route(self, prefix):
		self.prefixes.remove(ip_from_string(prefix, True))
		#Now we return whether it is empty or not
		if prefixes.count() == 0:
			return True
		else:
			return False

	def check_validity(self, attributes, next_hop):
		if self.attributes == attributes and self.next_hop == ip_from_string(next_hop):
			return True
		else:
			return False

#------------------------------------------------------------------------------
# AUXILIAR METHODS
#------------------------------------------------------------------------------
def ip_from_string(string, isprefix=False):
	if isprefix:
		FORMAT = "5B"
		ip = re.split('(.*)\.(.*)\.(.*)\.(.*)/(.*)', string)
		ip = ip[1:-1]
		#Pass the IP octects to integers
		ip = map(int, ip)
		#Returns the IP packed as an IP
		return struct.pack(FORMAT, ip[0], ip[1], ip[2], ip[3], ip[4])
	else:
		FORMAT = "4B"
		ip = string.split('.')
		#Pass the IP octects to integers
		ip = map(int, ip)
		#Returns the IP packed as an IP
		return struct.pack(FORMAT, ip[0], ip[1], ip[2], ip[3])

def ip_from_memory(memory, isprefix=False):
	if isprefix:
		FORMAT = "5B"
	else:
		FORMAT = "4B"
	#Unpack
	ip = list(struct.unpack(FORMAT, memory))
	ip = map(str, ip)
	if not isprefix:
		return '.'.join(ip)
	else:
		return '.'.join(ip[0:4]) + '/' + ip[4]

def saveResults(time, neighbors):
	with open('/root/conv_time', 'a') as dest:
		dest.write('Convergence time was ' + str(time) + ' for ' + str(neighbors) +' neighbors\n')
		dest.close()
	return


#------------------------------------------------------------------------------
# MAIN
#------------------------------------------------------------------------------
def main(argv):
	
	#Queue creation for passing the JSON messages received to the RIB processor
	q = Queue.Queue(0)
	#Queue(0) creates a queue of inf. size

	#RIB Processor Thread creation and start
	#Send as parameter the queue
	if len(argv) > 1:
		t = RIB(q=q, peers_number=int(argv[1]))
	else:
		t = RIB(q=q, peers_number=250)
	
	t.setName('RIB')
	t.start()
	counter = 0

	while 1:
		line = sys.stdin.readline().strip()
		#If parent process (exabgp) dies, then we only receive empty lines.
		#Receiving 50 lines is consider enough to exit.
		if line == "":
			counter += 1
			if counter > 50:
				#WARNING: Remains code to kill son's thread.
				exit(-1)
				break
			continue
		counter = 0
		q.put(line)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
