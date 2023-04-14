# CA687_Assignment2
# RYU Load Balancer and QoS Controller
OpenFlow SDN Load Balancer and QoS using the RYU controller

### Software Requirements
* OpenvSwitch version 2.9.5
* RYU version 4.15
* Mininet version 2.3.0d6
* Ubuntu 18.04.4 LTS

### Setup Environment
1. Install all above software requirements.
1. Run ` ryu-manager LoadBalancerAndQoSController.py` to start the controller.
1. Run `sudo python3 TestTopo.py` to start mininet and create the topology. When you `exit` mininet, the topology will be deleted automatically.
1. `h3`, `h4`, `h5`, `h6`, `h7` are load balancer servers, and `h1`and `h2` are the clients.
1. `h1` is priority client, `h6` and `h7` are priority servers.
1. the virtual ip of load balancer is 10.0.0.199.

### test
* send http request from h2: h2 wget 10.0.0.199
