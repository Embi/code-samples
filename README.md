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
A diagram showing networking a solution I implemented for redirecting ipv4
traffic over wireguard mash to honeypots running in on-premises infrastructure
while preserving source and destination (bot IP and VPS IP) in IP packets.

### [Ansible (Apache Druid)](ansible/druid)
Ansible playbook for deployment of a single instance Apache Druid columnar
DB that consumes datapoints from Apache Kafka, uses MinIO as deep storage and
PostgreSQL as metadata storage. 

### [Ansible (K8s)](ansible/k8s)
A sample with playbook showcasing initialization and deployment of a
HA (HAProxy with Keepalived with virtual IP address) K8S cluster.
