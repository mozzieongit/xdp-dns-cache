# XDP-based DNS hot cache

This is the code created for Research Project 1 during my study of
Security and Network Engineering at the University of Amsterdam.

It's a work (currently not) in progress. The goal was to create a caching layer
using XDP and TC, where XDP would be used to answer frequent queries to reduce
the burden on nameservers. It currently can only answer a query for the NS
records of `nl.`.
