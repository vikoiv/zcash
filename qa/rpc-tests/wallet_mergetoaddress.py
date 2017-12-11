#!/usr/bin/env python2
# Copyright (c) 2017 The Zcash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.authproxy import JSONRPCException
from test_framework.util import assert_equal, initialize_chain_clean, \
    start_node, connect_nodes_bi, sync_blocks, sync_mempools

import time
from decimal import Decimal

class WalletMergeToAddressTest (BitcoinTestFramework):

    def setup_chain(self):
        print("Initializing test directory "+self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 4)

    def setup_network(self, split=False):
        args = ['-debug=zrpcunsafe']
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, args))
        self.nodes.append(start_node(1, self.options.tmpdir, args))
        args2 = ['-debug=zrpcunsafe', '-mempooltxinputlimit=7']
        self.nodes.append(start_node(2, self.options.tmpdir, args2))
        connect_nodes_bi(self.nodes,0,1)
        connect_nodes_bi(self.nodes,1,2)
        connect_nodes_bi(self.nodes,0,2)
        self.is_network_split=False
        self.sync_all()

    # Returns txid if operation was a success or None
    def wait_and_assert_operationid_status(self, nodeid, myopid, in_status='success', in_errormsg=None):
        print('waiting for async operation {}'.format(myopid))
        opids = []
        opids.append(myopid)
        timeout = 300
        status = None
        errormsg = None
        txid = None
        for x in xrange(1, timeout):
            results = self.nodes[nodeid].z_getoperationresult(opids)
            if len(results)==0:
                time.sleep(1)
            else:
                status = results[0]["status"]
                if status == "failed":
                    errormsg = results[0]['error']['message']
                elif status == "success":
                    txid = results[0]['result']['txid']
                break
        print('...returned status: {}'.format(status))
        if errormsg is not None:
            print('  ...returned error: {}'.format(errormsg))
        assert_equal(in_status, status)
        if errormsg is not None:
            assert(in_errormsg is not None)
            assert_equal(in_errormsg in errormsg, True)
        return txid

    def run_test (self):
        print "Mining blocks..."

        self.nodes[0].generate(1)
        do_not_shield_taddr = self.nodes[0].getnewaddress()

        self.nodes[0].generate(4)
        walletinfo = self.nodes[0].getwalletinfo()
        assert_equal(walletinfo['immature_balance'], 50)
        assert_equal(walletinfo['balance'], 0)
        self.sync_all()
        self.nodes[2].generate(1)
        self.nodes[2].getnewaddress()
        self.nodes[2].generate(1)
        self.nodes[2].getnewaddress()
        self.nodes[2].generate(1)
        self.sync_all()
        self.nodes[1].generate(101)
        self.sync_all()
        assert_equal(self.nodes[0].getbalance(), 50)
        assert_equal(self.nodes[1].getbalance(), 10)
        assert_equal(self.nodes[2].getbalance(), 30)

        # Shield the coinbase
        myzaddr = self.nodes[0].z_getnewaddress()
        result = self.nodes[0].z_shieldcoinbase("*", myzaddr, 0)
        self.wait_and_assert_operationid_status(0, result['opid'])
        self.sync_all()
        self.nodes[1].generate(1)
        self.sync_all()

        # Prepare some UTXOs and notes for merging
        mytaddr = self.nodes[0].getnewaddress()
        mytaddr2 = self.nodes[0].getnewaddress()
        mytaddr3 = self.nodes[0].getnewaddress()
        result = self.nodes[0].z_sendmany(myzaddr, [
            {'address': do_not_shield_taddr, 'amount': 10},
            {'address': mytaddr, 'amount': 10},
            {'address': mytaddr2, 'amount': 10},
            {'address': mytaddr3, 'amount': 10},
            ], 1, 0)
        self.wait_and_assert_operationid_status(0, result)
        self.sync_all()
        self.nodes[1].generate(1)
        self.sync_all()

        # Merging will fail when trying to spend from watch-only address
        self.nodes[2].importaddress(mytaddr)
        try:
            self.nodes[2].z_mergetoaddress([mytaddr], myzaddr)
            assert(False)
        except JSONRPCException,e:
            errorString = e.error['message']
        assert_equal("Could not find any funds to merge" in errorString, True)

        # Merging will fail because fee is negative
        try:
            self.nodes[0].z_mergetoaddress("*", myzaddr, -1)
            assert(False)
        except JSONRPCException,e:
            errorString = e.error['message']
        assert_equal("Amount out of range" in errorString, True)

        # Merging will fail because fee is larger than MAX_MONEY
        try:
            self.nodes[0].z_mergetoaddress("*", myzaddr, Decimal('21000000.00000001'))
            assert(False)
        except JSONRPCException,e:
            errorString = e.error['message']
        assert_equal("Amount out of range" in errorString, True)

        # Merging will fail because fee is larger than sum of UTXOs
        try:
            self.nodes[0].z_mergetoaddress("*", myzaddr, 999)
            assert(False)
        except JSONRPCException,e:
            errorString = e.error['message']
        assert_equal("Insufficient funds" in errorString, True)

        # Merging will fail because transparent limit parameter must be at least 0
        try:
            self.nodes[0].z_mergetoaddress("*", myzaddr, Decimal('0.001'), -1)
            assert(False)
        except JSONRPCException,e:
            errorString = e.error['message']
        assert_equal("Limit on maximum number of UTXOs cannot be negative" in errorString, True)

        # Merging will fail because transparent limit parameter is absurdly large
        try:
            self.nodes[0].z_mergetoaddress("*", myzaddr, Decimal('0.001'), 99999999999999)
            assert(False)
        except JSONRPCException,e:
            errorString = e.error['message']
        assert_equal("JSON integer out of range" in errorString, True)

        # Merging will fail because shielded limit parameter must be at least 0
        try:
            self.nodes[0].z_mergetoaddress("*", myzaddr, Decimal('0.001'), 50, -1)
            assert(False)
        except JSONRPCException,e:
            errorString = e.error['message']
        assert_equal("Limit on maximum number of notes cannot be negative" in errorString, True)

        # Merging will fail because shielded limit parameter is absurdly large
        try:
            self.nodes[0].z_mergetoaddress("*", myzaddr, Decimal('0.001'), 50, 99999999999999)
            assert(False)
        except JSONRPCException,e:
            errorString = e.error['message']
        assert_equal("JSON integer out of range" in errorString, True)

        # Merge UTXOs from node 0 of value 30, standard fee of 0.00010000
        result = self.nodes[0].z_mergetoaddress([mytaddr, mytaddr2, mytaddr3], myzaddr)
        self.wait_and_assert_operationid_status(0, result['opid'])
        self.sync_all()
        self.nodes[1].generate(1)
        self.sync_all()

        # Confirm balances and that do_not_shield_taddr containing funds of 10 was left alone
        assert_equal(self.nodes[0].getbalance(), 10)
        assert_equal(self.nodes[0].z_getbalance(do_not_shield_taddr), Decimal('10.0'))
        assert_equal(self.nodes[0].z_getbalance(myzaddr), Decimal('39.99990000'))
        assert_equal(self.nodes[1].getbalance(), 40)
        assert_equal(self.nodes[2].getbalance(), 30)

        # Shield coinbase UTXOs from any node 2 taddr, and set fee to 0
        result = self.nodes[2].z_shieldcoinbase("*", myzaddr, 0)
        self.wait_and_assert_operationid_status(2, result['opid'])
        self.sync_all()
        self.nodes[1].generate(1)
        self.sync_all()

        assert_equal(self.nodes[0].getbalance(), 10)
        assert_equal(self.nodes[0].z_getbalance(myzaddr), Decimal('69.99990000'))
        assert_equal(self.nodes[1].getbalance(), 50)
        assert_equal(self.nodes[2].getbalance(), 0)

        # Merge all notes from node 0 into a node 0 taddr, and set fee to 0
        result = self.nodes[0].z_mergetoaddress("ANY_ZADDR", mytaddr, 0)
        self.wait_and_assert_operationid_status(0, result['opid'])
        self.sync_all()
        self.nodes[1].generate(1)
        self.sync_all()

        assert_equal(self.nodes[0].getbalance(), Decimal('79.99990000'))
        assert_equal(self.nodes[0].z_getbalance(do_not_shield_taddr), Decimal('10.0'))
        assert_equal(self.nodes[0].z_getbalance(mytaddr), Decimal('69.99990000'))
        assert_equal(self.nodes[0].z_getbalance(myzaddr), 0)
        assert_equal(self.nodes[1].getbalance(), 60)
        assert_equal(self.nodes[2].getbalance(), 0)

        # Merge all node 0 UTXOs together into a node 1 taddr, and set fee to 0
        self.nodes[1].getnewaddress() # Ensure we have an empty address
        n1taddr = self.nodes[1].getnewaddress()
        result = self.nodes[0].z_mergetoaddress("ANY_TADDR", n1taddr, 0)
        self.wait_and_assert_operationid_status(0, result['opid'])
        self.sync_all()
        self.nodes[1].generate(1)
        self.sync_all()

        assert_equal(self.nodes[0].getbalance(), 0)
        assert_equal(self.nodes[0].z_getbalance(do_not_shield_taddr), 0)
        assert_equal(self.nodes[0].z_getbalance(mytaddr), 0)
        assert_equal(self.nodes[0].z_getbalance(myzaddr), 0)
        assert_equal(self.nodes[1].getbalance(), Decimal('149.99990000'))
        assert_equal(self.nodes[1].z_getbalance(n1taddr), Decimal('79.99990000'))
        assert_equal(self.nodes[2].getbalance(), 0)

        # Generate 800 regular UTXOs on node 0, and 20 regular UTXOs on node 2
        mytaddr = self.nodes[0].getnewaddress()
        n2taddr = self.nodes[2].getnewaddress()
        self.nodes[1].generate(1000)
        self.sync_all()
        for i in range(800):
            self.nodes[1].sendtoaddress(mytaddr, 1)
        for i in range(20):
            self.nodes[1].sendtoaddress(n2taddr, 1)
        self.nodes[1].generate(1)
        self.sync_all()

        # Merging the 800 UTXOs will occur over two transactions, since max tx size is 100,000 bytes.
        # We don't verify mergingTransparentValue as UTXOs are not selected in any specific order, so value can change on each test run.
        # We set an unrealistically high limit parameter of 99999, to verify that max tx size will constrain the number of UTXOs.
        result = self.nodes[0].z_mergetoaddress([mytaddr], myzaddr, 0, 99999)
        assert_equal(result["mergingUTXOs"], Decimal('662'))
        assert_equal(result["remainingUTXOs"], Decimal('138'))
        assert_equal(result["mergingNotes"], Decimal('0'))
        assert_equal(result["mergingShieldedValue"], Decimal('0'))
        assert_equal(result["remainingNotes"], Decimal('0'))
        assert_equal(result["remainingShieldedValue"], Decimal('0'))
        remainingTransparentValue = result["remainingTransparentValue"]
        opid1 = result['opid']

        # Verify that UTXOs are locked (not available for selection) by queuing up another merging operation
        result = self.nodes[0].z_mergetoaddress([mytaddr], myzaddr, 0, 0)
        assert_equal(result["mergingUTXOs"], Decimal('138'))
        assert_equal(result["mergingTransparentValue"], Decimal(remainingTransparentValue))
        assert_equal(result["remainingUTXOs"], Decimal('0'))
        assert_equal(result["remainingTransparentValue"], Decimal('0'))
        assert_equal(result["mergingNotes"], Decimal('0'))
        assert_equal(result["mergingShieldedValue"], Decimal('0'))
        assert_equal(result["remainingNotes"], Decimal('0'))
        assert_equal(result["remainingShieldedValue"], Decimal('0'))
        opid2 = result['opid']

        # wait for both aysnc operations to complete
        self.wait_and_assert_operationid_status(0, opid1)
        self.wait_and_assert_operationid_status(0, opid2)

        # sync_all() invokes sync_mempool() but node 2's mempool limit will cause tx1 and tx2 to be rejected.
        # So instead, we sync on blocks and mempool for node 0 and node 1, and after a new block is generated
        # which mines tx1 and tx2, all nodes will have an empty mempool which can then be synced.
        sync_blocks(self.nodes[:2])
        sync_mempools(self.nodes[:2])
        # Generate enough blocks to ensure all transactions are mined
        while self.nodes[1].getmempoolinfo()['size'] > 0:
            self.nodes[1].generate(1)
        self.sync_all()

        # Verify maximum number of UTXOs which node 2 can shield is limited by option -mempooltxinputlimit
        # This option is used when the limit parameter is set to 0.
        result = self.nodes[2].z_mergetoaddress([n2taddr], myzaddr, Decimal('0.0001'), 0)
        assert_equal(result["mergingUTXOs"], Decimal('7'))
        assert_equal(result["remainingUTXOs"], Decimal('13'))
        assert_equal(result["mergingNotes"], Decimal('0'))
        assert_equal(result["remainingNotes"], Decimal('0'))
        self.wait_and_assert_operationid_status(2, result['opid'])
        self.sync_all()
        self.nodes[1].generate(1)
        self.sync_all()

        # Verify maximum number of UTXOs which node 0 can shield is set by default limit parameter of 50
        mytaddr = self.nodes[0].getnewaddress()
        for i in range(100):
            self.nodes[1].sendtoaddress(mytaddr, 1)
        self.nodes[1].generate(1)
        self.sync_all()
        result = self.nodes[0].z_mergetoaddress([mytaddr], myzaddr, Decimal('0.0001'))
        assert_equal(result["mergingUTXOs"], Decimal('50'))
        assert_equal(result["remainingUTXOs"], Decimal('50'))
        assert_equal(result["mergingNotes"], Decimal('0'))
        # Remaining notes are only counted if we are trying to merge any notes
        assert_equal(result["remainingNotes"], Decimal('0'))
        self.wait_and_assert_operationid_status(0, result['opid'])

        # Verify maximum number of UTXOs which node 0 can shield can be set by the limit parameter
        result = self.nodes[0].z_mergetoaddress([mytaddr], myzaddr, Decimal('0.0001'), 33)
        assert_equal(result["mergingUTXOs"], Decimal('33'))
        assert_equal(result["remainingUTXOs"], Decimal('17'))
        assert_equal(result["mergingNotes"], Decimal('0'))
        # Remaining notes are only counted if we are trying to merge any notes
        assert_equal(result["remainingNotes"], Decimal('0'))
        self.wait_and_assert_operationid_status(0, result['opid'])
        # Don't sync node 2 which rejects the tx due to its mempooltxinputlimit
        sync_blocks(self.nodes[:2])
        sync_mempools(self.nodes[:2])
        self.nodes[1].generate(1)
        self.sync_all()

        # Verify maximum number of notes which node 0 can shield can be set by the limit parameter
        result = self.nodes[0].z_mergetoaddress([myzaddr], myzaddr, 0, 50, 2)
        assert_equal(result["mergingUTXOs"], Decimal('0'))
        # Remaining UTXOs are only counted if we are trying to merge any UTXOs
        assert_equal(result["remainingUTXOs"], Decimal('0'))
        assert_equal(result["mergingNotes"], Decimal('2'))
        assert_equal(result["remainingNotes"], Decimal('3'))
        self.wait_and_assert_operationid_status(0, result['opid'])
        self.nodes[1].generate(1)
        self.sync_all()

if __name__ == '__main__':
    WalletMergeToAddressTest().main()
