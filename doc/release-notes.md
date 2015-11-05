(note: this is a temporary file, to be added-to by anybody, and moved to
release-notes at release time)

Notable changes
===============

`NODE_BLOOM` service bit
------------------------

Support for the `NODE_BLOOM` service bit, as described in [BIP
111](https://github.com/bitcoin/bips/blob/master/bip-0111.mediawiki), has been
added to the P2P protocol code.

BIP 111 defines a service bit to allow peers to advertise that they support
bloom filters (such as used by SPV clients) explicitly. It also bumps the protocol
version to allow peers to identify old nodes which allow bloom filtering of the
connection despite lacking the new service bit.

In this version, it is only enforced for peers that send protocol versions
`>=170011`. For the next major version it is planned that this restriction will be
removed. It is recommended to update SPV clients to check for the `NODE_BLOOM`
service bit for nodes that report versions newer than 170011.

Reduce upload traffic
---------------------

A major part of the outbound traffic is caused by serving historic blocks to
other nodes in initial block download state.

It is now possible to reduce the total upload traffic via the `-maxuploadtarget`
parameter. This is *not* a hard limit but a threshold to minimize the outbound
traffic. When the limit is about to be reached, the uploaded data is cut by not
serving historic blocks (blocks older than one week).
Moreover, any SPV peer is disconnected when they request a filtered block.

This option can be specified in MiB per day and is turned off by default
(`-maxuploadtarget=0`).
The recommended minimum is 144 * MAX_BLOCK_SIZE (currently 144MB) per day.

A more detailed documentation about keeping traffic low can be found in
[/doc/reducetraffic.md](/doc/reducetraffic.md).
