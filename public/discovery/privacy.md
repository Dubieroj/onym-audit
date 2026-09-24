# Privacy profile: Onym audit Discovery provider

The provider manifest, the catalog snapshots, the inclusion policies, the
status pages and this document are static files served without cookies,
access logs, or third-party requests. Fetching them tells this provider
nothing about who fetched them. Clients choose which listed auditors to
credit locally; the provider never learns it.

To build its services catalog, the provider's own server fetches Onym's
default Discovery catalog and the listed services' manifests. Those
requests carry no information about any client.
