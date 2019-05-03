
obj-y :=

#
# packet
#
obj-y += packet/packet_handle.o
obj-y += packet/packet_hook.o
obj-y += packet/packet_pool.o
obj-y += packet/packet_decode.o

#
# packet hook 
# 
# * NOTE: Plz take care of prio. The order here's important.
#
obj-y += packet/hook/ipfrag/ipfrag.o
obj-y += packet/hook/pdump/pdump.o
obj-y += packet/hook/stat/stat.o

#
# conf
#
obj-y += conf/conf.o

#
# macdb
#
obj-y += macdb/macdb.o
# obj-y += macdb/macdb_arph.o

#
# ctk (connection tracking)
#
obj-y += ctk/ctk.o

#
# main
#
obj-y += op_monitor.o
obj-y += op_pcap_l2eth.o

obj-y += main.o
