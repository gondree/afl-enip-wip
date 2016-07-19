from scapy.all import *
import numpy as np
import matplotlib.pyplot as plt

list = []
listx = []
list2 = []
pairs = []
xy = []
pkts = rdpcap("fuzz-nop-class-rslogix.pcap")

for pkt in pkts:
    list.append("%.6F" % pkt.time)
    pairs = zip(list[0::2], list[1::2])
nl = [tuple(float(x) for x in t) for t in pairs]
for tup in nl:
    x,y = tup
    result = y-x
    list2.append(result)
    listx.append(x)
listx[:] = [x-1468015380.000000 for x in listx]
# xy = zip(listx, list2)
# plt.scatter(*zip(*xy), 'ko', markersize=2)
# plt.show()

plt.plot(listx, list2, 'ko', markersize=2)
plt.show()
print "Finished!"
#
#
# list = [('1468340530.635599', '1468340530.649285'), ('1468340530.676953', '1468340530.689486')]
# nl = [tuple(float(x) for x in t) for t in list]
# list2 = []
# listx = []
# xy = []
# # print nl
# for tup in nl:
#     x,y = tup
#     result = y - x
#     list2.append(result)
#     listx.append(x)
# listx[:] = [x-1468340400.000000 for x in listx]
# xy = zip(listx, list2)
# print xy
# plt.scatter(*zip(*xy))
# plt.show()

# for pkt in pkts:
#     list.append("%.6F" % pkt.time)
#     pairs = zip(list[0::2], list[1::2])
# print pairs
# for tup in pairs:
#     x,y = tup
#     result = int(float(y) - float(x))
#     list2.append("%.6F" % result)
# print list2
