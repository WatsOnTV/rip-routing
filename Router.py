#!/usr/bin/python3

"""
   Title: COSC 364 Internet Technologies and Engineering - First Assignment
   Description: Implementation of a routing demon based on parts of the RIPv2 protocol.
   Author: Megan Steenkamp (Student ID: 23459587)
   Author: Daniel Watson (Student ID: 32227228)
   Example run command: python3 ./Router.py router1.txt
   Date: April-May 2020
"""
import sys
import socket
import re
import random
import struct
import time
import os
import threading
from select import select
from prettytable import PrettyTable


# ============================================ THREADING TIMER ============================================#


class IntervalTimer:
    """ Interval timer using threading to execute a periodic function every given interval """

    # Constant
    JITTER_VALUE = 0.2


    def __init__(self, interval, hFunction, *args, **kwargs):
        """ Initialize the timer """
        self.start_time = None
        self._timer = None
        self.period = None
        self.interval = interval
        self.hFunction = hFunction
        self.args = args
        self.kwargs = kwargs
        self.is_running = False
        self.start()


    def __str__(self):
        """ String representation of elapsed time """
        elapsed_time = self.get_elapsed_time()
        return f"{elapsed_time:0.2f}"


    def get_elapsed_time(self):
        """ Get time elapsed since timer started """
        if self.start_time:
            return time.perf_counter() - self.start_time
        else:
            return 0.00


    def _run(self):
        """ Run the function associated with the timer """
        self.is_running = False
        self.start()
        self.hFunction(*self.args, **self.kwargs)


    def start(self):
        """ Start a new timer. Uniformly distribute period over range [0.8*interval, 1.2*interval] """
        if not self.is_running:
            self.start_time = time.perf_counter()
            period = self.interval * (1 + (random.uniform(-self.JITTER_VALUE, self.JITTER_VALUE)))
            self.period = period
            self._timer = threading.Timer(period, self._run)
            self._timer.start()
            self.is_running = True


    def stop(self):
        """ Stop timer """
        if self.start_time is not None:
            self._timer.cancel()
            self.start_time = None
            self.is_running = False


# ============================================ RIPv2 PACKET ============================================#

class RIPPacket:
    """ Class representing a RIPv2 response which will consist of a header and a up to 25 RTEs """

    # Class constants, packet constraints
    HEADER_LEN_B = 4
    RTE_LEN_B = 20
    MAX_LEN_B = HEADER_LEN_B + (25 * RTE_LEN_B)


    def __init__(self, rawdata=None, header=None, rtes=None):
        """ Initialize a RIP packet """
        self.header = None
        self.rtes = []

        if rawdata:
            self._init_from_net(rawdata)
        elif header and rtes:
            self._init_from_self(header, rtes)
        else:
            raise ValueError("Invalid data to initialize a RIPv2 packet")


    def _init_from_net(self, data):
        """ Initialize a RIP packet with data from another router. Unpack to header and body and
            and send to PacketHeader and PacketRTE classes
        """
        if len(data) > self.MAX_LEN_B:
            raise ValueError("Invalid data: packet is longer than maximal correct length")

        if len(data) < self.HEADER_LEN_B:
            raise ValueError("Invalid data: full header not supplied")

        # Validate route entries
        is_corrupt = (len(data) - self.HEADER_LEN_B) % self.RTE_LEN_B
        if is_corrupt:
            raise ValueError("Invalid data: packet is corrupt")

        self.header = PacketHeader(rawdata=data[0:self.HEADER_LEN_B])

        num_rtes = int((len(data) - self.HEADER_LEN_B) / self.RTE_LEN_B)
        start = self.HEADER_LEN_B
        end = start + self.RTE_LEN_B
        for i in range(num_rtes):
            self.rtes.append(PacketRTE(rawdata=data[start:end]))
            start += self.RTE_LEN_B
            end += self.RTE_LEN_B


    def _init_from_self(self, header, rtes):
        """ Initialize a RIP packet with imported data """
        self.header = header
        self.rtes = rtes


    def serialize(self):
        """ Format packet into btye representation """
        packet = self.header.serialize()
        for rte in self.rtes:
            packet += rte.serialize()

        return packet


# ============================================ RIPv2 PACKET HEADER ============================================#


class PacketHeader:
    """ Class representing the header of a RIPv2 response message """

    # Constants
    FORMAT = ">BBH"  # Big endian format. Two unsigned chars B (1 byte) (for command and version)
    # followed by H for a unsigned short for router ID (2 bytes).
    COMMAND = 2
    VERSION = 2


    def __init__(self, my_id=None, rawdata=None):
        """ Initialize a packet header """
        self.command = None
        self.version = None
        self.r_id = None

        if rawdata:
            self._init_from_net(rawdata)
        elif my_id:
            self._init_from_self(my_id)
        else:
            raise ValueError("Invalid data to initialize a RIPv2 header")


    def _init_from_net(self, rawdata):
        """ Initialize a RIPv2 packet with data from another router """
        header = struct.unpack(self.FORMAT, rawdata)
        command = int(header[0])
        version = int(header[1])
        r_id = int(header[2])

        # Validate header
        if command != self.COMMAND or version != self.VERSION:
            raise ValueError("Invalid data to initialize a RIPv2 header")
        if not 0 <= r_id <= 64000:
            raise ValueError("Invalid router ID for RIPv2 header")

        self.command = command
        self.version = version
        self.r_id = r_id


    def _init_from_self(self, my_id):
        """ Initialize a RIP packet with imported data """
        self.command = self.COMMAND
        self.version = self.VERSION
        self.r_id = my_id


    def serialize(self):
        """ Format header into btye representation """
        return struct.pack(self.FORMAT, self.command, self.version, self.r_id)


# ============================================ RIPv2 PACKET RTE ============================================#


class PacketRTE:
    """ Class representing a single Routing Table Entry in a RIPv2 response message """

    # Constants
    FORMAT = ">HHIIII"  # Big endian format, 2x unsigned short (2 bytes), 4x unsigned int (4 bytes)
    AFI = 2
    ROUTE_TAG = 0
    SUBNET_MASK = 0
    MIN_METRIC = 0
    MAX_METRIC = 16


    def __init__(self, rawdata=None, my_id=None, dest_id=None, metric=None):
        """ Initialize a RIPv2 routing table entry """
        self.afi = None
        self.route_tag = None
        self.dest_id = None
        self.subnet_mask = None
        self.next_hop = None
        self.metric = None

        if rawdata:
            self._init_from_net(rawdata)
        elif my_id and dest_id and metric:
            self._init_from_self(my_id, dest_id, metric)
        else:
            raise ValueError("Invalid data to initialize a routing table entry")


    def _init_from_net(self, rawdata):
        """ Initialize a RIP packet with data from another router """
        rte = struct.unpack(self.FORMAT, rawdata)

        afi = int(rte[0])
        route_tag = int(rte[1])
        dest_id = int(rte[2])
        subnet_mask = int(rte[3])
        next_hop = int(rte[4])
        metric = int(rte[5])

        # Validate rte
        if afi != self.AFI or route_tag != self.ROUTE_TAG or subnet_mask != self.SUBNET_MASK:
            raise ValueError("Invalid RTE provided")
        if not 0 <= dest_id <= 64000 or not 0 <= next_hop <= 64000:
            raise ValueError("Invalid router ID provided for RTE")

        if not self.MIN_METRIC <= metric <= self.MAX_METRIC:
            raise ValueError("Invalid metric provided for RTE")

        # Initialize
        self.afi = int(afi)
        self.route_tag = int(route_tag)
        self.dest_id = int(dest_id)
        self.subnet_mask = int(subnet_mask)
        self.next_hop = int(next_hop)
        self.metric = int(metric)


    def _init_from_self(self, my_id, dest_id, metric):
        """ Initialize a RIP packet with imported data """
        self.afi = self.AFI
        self.route_tag = self.ROUTE_TAG
        self.dest_id = int(dest_id)
        self.subnet_mask = self.SUBNET_MASK
        self.next_hop = int(my_id)
        self.metric = int(metric)


    def serialize(self):
        """ Format RTE into byte representation """
        return struct.pack(self.FORMAT, self.afi, self.route_tag, self.dest_id,
                           self.subnet_mask, self.next_hop, self.metric)


# ============================================ FSM STATES ============================================#


class State:
    """ Generic State superclass """


    def __init__(self, fsm):
        """ Initialize generic state """
        self.fsm = fsm


    def run(self):
        """ Common class implemented by all children """
        pass


    def __str__(self):
        """ Return string of state for debugging purposes """
        return self.__class__.__name__


# ============================================ STARTING STATE ============================================#


class Starting(State):
    """ Represents the state of the router when it first starts up,
        processes config file and populates routing table
    """

    # Constant
    HOST = '127.0.0.1'


    def __init__(self, fsm):
        """ Initialise Starting state from superclass """
        super(Starting, self).__init__(fsm)


    def run(self):
        """Read the given configuration file to set router variables and
           populate the initial routing table
        """

        router_id = None
        inputs = None
        outputs = None

        # Initialize with default values specified by RIPv2 protocol
        update_interval_s = 30
        route_timeout_s = 180
        garbage_collection_s = 120

        try:
            file = open(self.fsm.router.config_filename, 'r')
            for line in file.readlines():
                if line.startswith("router-id"):
                    router_id = self.validate_id(line)
                if line.startswith("input-ports"):
                    inputs = self.validate_inputs(line)
                if line.startswith("outputs"):
                    outputs = self.validate_outputs(line)
                if line.startswith("update-interval"):
                    update_interval_s = self.validate_time(line)
                if line.startswith("route-timeout"):
                    route_timeout_s = self.validate_time(line)
                if line.startswith("garbage-timeout"):
                    garbage_collection_s = self.validate_time(line)
            file.close()
        except IOError as e:
            ValueError(e)

        # Validate the config file
        if router_id is None:
            raise ValueError("Incorrect Configuration File Format: 'router-id' line is missing")
        elif inputs is None:
            raise ValueError("Incorrect Configuration File Format: 'input-ports' line is missing")
        elif len(inputs) == 0:
            raise ValueError("Incorrect Configuration File Format: no input ports provided")
        elif outputs is None:
            raise ValueError("Incorrect Configuration File Format: 'outputs' line is missing")
        elif len(outputs) == 0:
            raise ValueError("Incorrect Configuration File Format: no output ports provided")

        self.validate_in_out(inputs, outputs)

        # Variables are now validated
        # Can now set router ID, input sockets, neighbours and initial routing table
        self.fsm.router.r_id = router_id
        self.fsm.router.update_interval_s = update_interval_s
        self.fsm.router.timeout_interval_s = route_timeout_s
        self.fsm.router.garbage_interval_s = garbage_collection_s
        self.add_input_sockets(inputs)
        for output in outputs:
            port = output.split("-")[0]
            metric = output.split("-")[1]
            n_id = output.split("-")[2]
            self.fsm.router.neighbours[int(n_id)] = int(port)
            self.fsm.router.neighbour_config_metrics[int(n_id)] = int(metric)
            self.fsm.router.neighbour_status[int(n_id)] = time.perf_counter()
        self.populate_table(outputs)

        # Start threading event for sending regular updates
        self.fsm.router.update_timer = IntervalTimer(self.fsm.router.update_interval_s, self.fsm.router.regular_update)

        # Start timer to print routing table for demo
        # Print table every 5 seconds
        self.fsm.router.print_timer = IntervalTimer(5, self.fsm.router.print_routing_table)

        # Set to transition to change to Waiting state
        self.fsm.transition = "toWaiting"


    @staticmethod
    def validate_time(line):
        """Validates given timer timeout value"""
        if len(line.split()) != 2:  # Check exactly one time value is provided
            raise ValueError("Please include one timer value")
        try:
            time_s = int(line.split()[1])
        except ValueError:
            raise ValueError(f"'{line.split()[1]}' is not a valid integer time value (s)")

        return time_s


    @staticmethod
    def validate_id(line):
        """Validates given router ID"""
        if len(line.split()) != 2:  # Check exactly one router-id is provided
            raise ValueError("Please include one router-id")
        try:
            router_id = int(line.split()[1])
        except ValueError:
            raise ValueError(f"'{line.split()[1]}' is not a valid router-id")
        if not (1 <= router_id <= 64000):
            raise ValueError("Router-id must be between 1 and 64000")

        return router_id


    @staticmethod
    def validate_inputs(line):
        """Processes the line and returns the inputs in an array"""
        inputs = line.strip().replace(',', '').split(' ')[1:]
        for port in inputs:
            if not port.isdigit():
                raise ValueError(f"Parsing input port: '{port}' is not an integer")
            if not (1024 <= int(port) <= 64000):
                raise ValueError(f"Parsing input port {port}: Out of valid range")
            if inputs.count(port) > 1:
                raise ValueError(f"Input port {port} in config file more than once")

        return inputs


    @staticmethod
    def validate_outputs(line):
        """Processes the line and return the outputs in an array"""
        line = line.replace('outputs', '')
        info = line.strip().replace(' ', '').split(',')
        outputs = []
        r_ids = []
        for output in info:
            match = re.search(r'\d+-\d+-\d+', output)
            if match:
                outputs.append(match.group(0))
            else:
                raise ValueError(f"Incorrect output format '{output}'. Example format: 5000-1-1")

        for i, output in enumerate(outputs):
            port = output.split("-")[0]
            metric = output.split("-")[1]
            r_id = output.split("-")[2]
            if not (1024 <= int(port) <= 64000):
                raise ValueError(f"Error parsing output port {port}: Out of valid range")
            if outputs.count(info) > 1:
                raise ValueError(f"Output port {port} in config file more than once")
            if not (1 <= int(metric) <= 15):
                raise ValueError(f"Port {port} has an invalid metric of {metric}")
            if r_id in r_ids:
                raise ValueError(f"Router ID {r_id} in config file more than once")
            else:
                r_ids.append(r_id)

        return outputs


    @staticmethod
    def validate_in_out(inputs, outputs):
        """Checks if inputs and outputs have any common ports"""
        for port in outputs:
            port_num = port.split('-')[0]
            if port_num in inputs:
                raise ValueError(f"Port {port_num} is both an input and output")


    def add_input_sockets(self, inputs):
        """ Creates a UDP port for each input socket listed in the configuration file """
        for port in inputs:
            try:
                soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                soc.bind((self.HOST, int(port)))
                self.fsm.router.input_sockets.append(soc)
            except socket.error as e:
                raise ValueError(f"Error creating socket on port {port}: {e}")


    def populate_table(self, outputs):
        """ Populates routing table with directly-connected routers as specified by
            the configuration file
        """
        for output in outputs:
            port = output.split("-")[0]
            metric = output.split("-")[1]
            r_id = output.split("-")[2]

            rte = RTE(self.fsm.router, r_id, metric, "dir", port)
            self.fsm.router.table.add_rte(rte)


# ============================================ WAITING STATE ============================================#


class Waiting(State):
    """ Represents the state of the router waiting for an update """


    def __init__(self, fsm):
        """ Initialise Waiting state from superclass """
        super(Waiting, self).__init__(fsm)


    def run(self):
        """ Waits for an incoming message from an existing input socket.
            If a message is available, the state is changed to 'Processing'
        """
        incoming, _, errors = select(self.fsm.router.input_sockets, [], [], 1000)
        if len(errors) > 0:
            raise ValueError(f"Error getting message on socket {errors[0].getsockname()}")
        if len(incoming) > 0:
            self.fsm.transition = "toReceiving"
            self.fsm.router.sockets_with_messages = incoming


# ============================================ PROCESSING STATE ============================================#


class Processing(State):
    """ Represents the state of the router when it has received an incoming update """

    BUFFER_SIZE = 2048


    def __init__(self, fsm):
        """ Initialise Receiving state from superclass """
        super(Processing, self).__init__(fsm)


    def receive_all(self, sock):
        """ Loop to receive all data from a socket """
        data = b''
        while True:
            part = sock.recv(self.BUFFER_SIZE)
            data += part
            if len(part) < self.BUFFER_SIZE:
                break
        return data


    def run(self):
        """ Gets inbound packet and processes it, updating routing table and triggering
            updates as required.
        """
        received = []
        for sock in self.fsm.router.sockets_with_messages:
            data = self.receive_all(sock)

            # Try to form a RIP packet with the received data. If a packet object cannot be formed, or
            # an error is thrown when making it, it must be erroneous. Therefore, ignore the packet.
            try:
                packet = RIPPacket(rawdata=data)
            except ValueError as e:
                self.fsm.transition = "toWaiting"
                return

            is_from_neighbour = False
            for n_id, n_port in self.fsm.router.neighbours.items():
                if n_id == packet.header.r_id:
                    is_from_neighbour = True
                    self.fsm.router.neighbour_status[int(n_id)] = time.perf_counter()
                    # Re-initialize timeout as we have heard from neighbour IF we are using the direct route to them
                    neighbour = self.fsm.router.table.get_rte(n_id)
                    if not neighbour:
                        # Special case if neighbour went down but is now back
                        metric = self.fsm.router.neighbour_config_metrics[int(n_id)]
                        rte = RTE(self.fsm.router, n_id, metric, "dir", n_port)
                        self.fsm.router.table.add_rte(rte)
                    else:
                        if neighbour.next_hop_id == 'dir':
                            neighbour.timeout_timer.stop()
                            neighbour.timeout_timer.start()

            if is_from_neighbour:
                received.append(packet)

        self.fsm.router.sockets_with_messages = []

        for packet in received:
            self.fsm.router.update_table(packet)

        self.fsm.transition = "toWaiting"


# ============================================ SHUTTING DOWN STATE ============================================#


class ShuttingDown(State):
    """ Represents the state of the router when it is shut down by a keyboard interrupt """


    def __init__(self, fsm):
        """ Initialise shutting down state from superclass """
        super(ShuttingDown, self).__init__(fsm)


    def run(self):
        """ Closes all UDP input ports that were previously bound """
        # Stop running threading event for a regular update
        # Stop router print output table for demo
        self.fsm.router.print_timer.stop()
        self.fsm.router.update_timer.stop()
        self.fsm.router.table.stop_rte_timers()
        for sock in self.fsm.router.input_sockets:
            sock.close()
        sys.exit()


# ============================================ ROUTER FSM ============================================#


class RouterStateMachine(object):
    """ Implementation of Router as a Finite State Machine """


    def __init__(self, router):
        """ Initialize router as a finite state machine """
        self.router = router
        self.state = Starting(self)  # Router is initialized in the starting state
        self.transition = None


    def change_state(self, transition_name):
        """ Update the current transition of the Router FSM """
        if transition_name == "toWaiting":
            self.state = Waiting(self)
        elif transition_name == "toReceiving":
            self.state = Processing(self)
        elif transition_name == "toShuttingDown":
            self.state = ShuttingDown(self)


    def run(self):
        """ Runs the Router FSM """
        if self.transition:
            self.change_state(self.transition)
            self.transition = None
        self.state.run()


# ============================================ ROUTING TABLE ENTRY ============================================#


class RTE:
    """ Class representing a Routing Table Entry.
        Initializes a routing table entry which will store the following information
            for a destination:
                    Integer: router-id of destination
                    Integer: metric to destination
                    Integer: router-id of next hop to get to destination
                    Boolean: route change flag
    """

    # Constants
    MIN_METRIC = 0
    MAX_METRIC = 16


    def __init__(self, router, dest_id, metric, next_hop_id, next_hop_port):
        """ Initializes a routing table entry """
        self.router = router
        self.dest_id = int(dest_id)
        self.metric = int(metric)
        if next_hop_id != 'dir':
            self.next_hop_id = int(next_hop_id)
        else:
            self.next_hop_id = next_hop_id
        self.next_hop_port = int(next_hop_port)
        self.is_changed = True
        self.timeout_timer = IntervalTimer(self.router.timeout_interval_s, self.router.invalidate_route, self)
        self.garbage_timer = None


    def __str__(self):
        return f"Destination ID: {self.dest_id}, Metric: {self.metric}, Next hop: {self.next_hop_id}"


    def is_equal(self, dest_id, metric, next_hop_id):
        """ Check the equality of two RIPv2 route entries for when they are removed from table"""
        return self.dest_id == dest_id and self.metric == metric and self.next_hop_id == next_hop_id


    def list_rte(self):
        """ Returns a list of all information for a RTE """
        garbage_timer = str(self.garbage_timer)
        if garbage_timer == "None":
            garbage_timer = "0.00"
        return [self.dest_id, self.metric, self.next_hop_id, self.is_changed,
                str(self.timeout_timer), garbage_timer]


    def stop_timeout_timer(self):
        """ Stops timeout timer for a route """
        if self.timeout_timer:
            self.timeout_timer.stop()


    def stop_garbage_timer(self):
        """ Stops timeout timer for a route """
        if self.garbage_timer:
            self.garbage_timer.stop()


    def stop_timers(self):
        """ Stop all threading timers associated with a route """
        self.stop_timeout_timer()
        self.stop_garbage_timer()


# ============================================ ROUTING TABLE ============================================#


class RoutingTable:
    """ Stores a collection of routing table entries """


    def __init__(self, router):
        """ Initializes an empty routing table """
        self.router = router
        self.table = []


    def pprint_table(self):
        """ Uses the prettyprint module to print the table """
        t = PrettyTable(['Destination ID', 'Metric', 'Next-hop ID', 'Route Change',
                         'Timeout (s)', 'Garbage (s)'])
        for rte in self.table:
            t.add_row(rte.list_rte())
        return t.get_string(sortby='Destination ID', reversesort=False)


    def get_rte(self, r_id):
        """ Return known metric to a given router ID """
        for rte in self.table:
            if rte.dest_id == r_id:
                return rte


    def add_rte(self, rte):
        """ Adds an RTE to the table """
        self.table.append(rte)


    def remove_rte(self, rte):
        """ Removes an RTE from the table """
        rte.stop_timers()
        self.table.remove(rte)


    def stop_rte_timers(self):
        """ Stops all timers associated with the routing table """
        for rte in self.table:
            rte.stop_timers()


# ============================================ ROUTER ============================================#


class Router:
    """Initializes a class to add the information for the router from the 
       configuration file.
    """

    # Constants
    HOST = '127.0.0.1'
    MIN_METRIC = 0
    MAX_METRIC = 16


    def __init__(self, config_filename):
        self.fsm = RouterStateMachine(self)
        self.config_filename = config_filename
        self.r_id = None

        self.table = RoutingTable(self)
        self.neighbours = {}  # Directly connected neighbours (outputs). Dict of id: port.
        self.neighbour_config_metrics = {}  # Dictionary of id: metric.
        self.neighbour_status = {}  # Dictionary of id: time since update.
        self.input_sockets = []
        self.sockets_with_messages = []

        # Timer-related fields
        self.update_interval_s = None
        self.timeout_interval_s = None
        self.garbage_interval_s = None
        self.update_timer = None

        self.lock = threading.RLock()

        # Add periodic timer to print routing table for demo
        self.print_timer = None


    def start_demon(self):
        """The main part of the program, enters an infinite loop and reacts to incoming events"""
        while True:
            try:
                self.fsm.run()
            except ValueError as e:
                print(f"Error: {e}")
                self.fsm.change_state("toShuttingDown")
                self.fsm.run()
            except KeyboardInterrupt:
                self.fsm.change_state("toShuttingDown")
                self.fsm.run()
            except Exception as e:
                print(f"An unknown error has occurred: \n\n {e} \n\n Shutting down router.")
                self.fsm.change_state("toShuttingDown")
                self.fsm.run()


    def print_routing_table(self):
        """ Print routing table in tabular format """
        print(f"Router ID: {self.r_id}")
        print(self.table.pprint_table())


    def update_table(self, packet):
        """ Process packet, updating RTEs where necessary """
        self.lock.acquire()
        try:
            sender_id = packet.header.r_id
            sender_details = self.table.get_rte(sender_id)
            sender_metric = sender_details.metric

            next_hop = sender_details.next_hop_id
            if next_hop == 'dir':
                next_hop = sender_id
            next_port = sender_details.next_hop_port

            for rte in packet.rtes:
                # Check the destination is not myself
                if rte.dest_id == self.r_id:
                    continue

                rte_table = self.table.get_rte(rte.dest_id)
                new_metric = min((rte.metric + sender_metric), self.MAX_METRIC)

                # Check if rte already exists for this destination
                if not rte_table:
                    if not new_metric == self.MAX_METRIC:
                        rte = RTE(self, rte.dest_id, new_metric, next_hop, next_port)
                        self.table.add_rte(rte)
                    # else drop packet
                else:
                    if sender_id == rte_table.next_hop_id:
                        # If route is newly invalid
                        if new_metric == self.MAX_METRIC:  # Will not restart timers for an invalid route
                            if rte_table.metric != self.MAX_METRIC:
                                self.invalidate_route(rte_table)
                        else:
                            # Metric has changed but is still valid
                            if new_metric != rte_table.metric:
                                rte_table.metric = new_metric
                                rte_table.next_hop_id = next_hop
                                rte_table.next_hop_port = next_port
                                rte_table.is_changed = True
                            # Restart timers
                            rte_table.stop_timers()
                            rte_table.timeout_timer.start()
                    else:
                        # We may have a new best route for a destination
                        if new_metric < rte_table.metric or \
                                (new_metric == rte_table.metric and
                                 rte_table.timeout_timer.get_elapsed_time() >= (0.5 * self.timeout_interval_s) and not
                                 rte_table.is_equal(rte.dest_id, new_metric, next_hop)):
                            # Check this new route isn't the same as what we already have
                            rte_table.metric = new_metric
                            rte_table.next_hop_id = next_hop
                            rte_table.next_hop_port = next_port
                            rte_table.is_changed = True
                            rte_table.stop_timers()
                            rte_table.timeout_timer.start()
        finally:
            self.lock.release()


    def process_packet_rte(self, n_id, rte):
        """ Process packet implementing split horizon. Return a PacketRTE object """

        # Consider special case where we have kept neighbour in table but they are down
        if rte.metric == self.MAX_METRIC and not rte.is_changed and not rte.timeout_timer.is_running:
            return

        # Else implement split horizon processing
        metric = rte.metric
        if n_id == rte.next_hop_id:
            metric = self.MAX_METRIC

        return PacketRTE(my_id=self.r_id, dest_id=rte.dest_id, metric=metric)


    def regular_update(self):
        """ Send unsolicited response message every [4.8, 5.2] seconds to each neighbour with complete routing table """
        header = PacketHeader(my_id=self.r_id)
        for n_id, n_port in self.neighbours.items():
            # Check neighbour has not been invalidated
            if self.table.get_rte(n_id):
                rtes = []
                for rte in self.table.table:
                    packet_rte = self.process_packet_rte(n_id, rte)
                    if packet_rte:
                        rtes.append(packet_rte)

                if rtes:
                    message = RIPPacket(header=header, rtes=rtes)
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    # Send message to neighbour on specified port
                    sock.sendto(message.serialize(), (self.HOST, n_port))

        # Clear route change flags
        for rte in self.table.table:
            if rte.is_changed:
                rte.is_changed = False


    def trigger_update(self):
        """ Set a timer for 1-5 seconds. If an unsolicited response is not due in this time,
            send a triggered update to each neighbour for each route with the route change flag set.
        """

        # Generate a random value between 1 and 5 seconds.
        # If an unsolicited Response message is due in this time, drop the update
        update_time = random.uniform(1, 5)
        if self.update_timer.get_elapsed_time() + update_time >= self.timeout_interval_s:
            return

        header = PacketHeader(my_id=self.r_id)
        for n_id, n_port in self.neighbours.items():
            # Check neighbour has not gone down
            if self.table.get_rte(n_id):  # Special case where we may have removed a neighbour from table
                if self.table.get_rte(n_id).metric != self.MAX_METRIC:
                    rtes = []
                    for rte in self.table.table:
                        if rte.is_changed:
                            packet_rte = self.process_packet_rte(n_id, rte)
                            rtes.append(packet_rte)

                    if rtes:
                        message = RIPPacket(header=header, rtes=rtes)
                        soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        # Send message to neighbour on specified port
                        soc.sendto(message.serialize(), (self.HOST, n_port))

        # Clear route change flags
        for rte in self.table.table:
            if rte.is_changed:
                rte.is_changed = False


    def invalidate_route(self, rte):
        """ Triggered when a route becomes invalid (timer or update). Starts garbage collection timer, changes metric
            and route change flag for route
        """
        self.lock.acquire()
        try:
            # Check for special case where we are invalidating a learned route with a destination that is a directly
            # connected neighbour. In this case we can revert to our directly connected route
            for n_id in self.neighbours.keys():
                time_since_update = time.perf_counter() - self.neighbour_status[int(n_id)]
                if n_id == rte.dest_id and rte.next_hop_id != "dir" and time_since_update < (
                        0.5 * self.timeout_interval_s):
                    rte.metric = self.neighbour_config_metrics[int(n_id)]
                    rte.next_hop_id = "dir"
                    rte.stop_timers()
                    rte.timeout_timer.start()

                    # Release lock on thread
                    self.lock.release()
                    return

            rte.timeout_timer.stop()
            rte.garbage_timer = IntervalTimer(self.garbage_interval_s, self.remove_route, rte)
            rte.metric = self.MAX_METRIC
            rte.is_changed = True

            self.trigger_update()

        finally:
            self.lock.release()


    def remove_route(self, rte):
        """ Deletes a RTE from routing table """
        self.lock.acquire()
        try:
            self.table.remove_rte(rte)
        finally:
            self.lock.release()


# ============================================ MAIN ============================================#


def validate_filename():
    """Check a *.txt file has been provided as command line argument, and this file exists"""
    try:
        filename = sys.argv[1]
    except IndexError:
        sys.exit("Error: Please include configuration file name")
    if not filename.endswith(".txt"):
        sys.exit("Error: filename must be of type *.txt")
    if not os.path.exists(filename):
        sys.exit(f"Error: {filename} does not exist")
    return filename


def main():
    """Main function to execute program"""

    if __name__ == "__main__":
        router = Router(validate_filename())
        router.start_demon()


main()
