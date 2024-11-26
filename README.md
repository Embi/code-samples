This repository contains a few small software engineering samples from various projects that I worked on.
The presented code is by no means complete and serves only for code style/culture presentation.

### [Python (oidc)](python/oidc)
Fully tested and civilized (i.e. with proper documentation and type annotations)
implementation of an OIDC client that allows for easy implementation of various
OIDC backends (this solution showcases two backends: Fusionauth and Auth0).

### [Python (Ipv4 whitelisting/blacklisting)](python/ipv4-whitelisting)
A solution for excluding certain ip addresses/ranges from large (100k-1M)
lists of ip addresses. The solution utilizes deterministic finite automata.

### [Architecture](architecture)
A very simple software/system architecture that I designed and implemented as
an MVP for a fin-tech startup Tailor Invest s.r.o. (the company does not exist
anymore) in 2018. Everything in the diagram was designed and implemented by me
in a span of roughly 5 months with two AWS environments (DEV, PROD) and a hardened
network with VPN access. The solution also included a relatively complex
multi-tenant database model.

### [Networking](networking)
A diagram showing a networking solution I implemented for redirecting incoming 
ipv4 traffic over wireguard "mash" to infrastructure running on premises.
The caveat of the solution was to preserve source and destination in IP
packets over all hops (i.e., reverse proxy was not an option). Also based on
packets destination port, the packets were routed to different on-premises
servers for processing. The whole solution (e.g., adding new VPS or adding new
processing on-prem server) was fully automated with Ansible playbooks.

### [Ansible (Apache Druid)](ansible/druid)
Ansible playbook for deployment of a single instance Apache Druid columnar
DB that consumes datapoints from Apache Kafka, uses MinIO as deep storage and
PostgreSQL as metadata storage. 

### [Ansible (K8s)](ansible/k8s)
A sample with playbook showcasing initialization and deployment of a
HA (HAProxy with Keepalived with virtual IP address) K8S cluster.
