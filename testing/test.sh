
make

echo ""
echo "- - - TEST 1 - - - - -"
echo ""
../p1 inputs/trafficArpIcmp.pcap | diff - expected/expectedOutput1.txt

echo ""
echo "- - - TEST 2 - - - - -"
echo ""
../p1 inputs/trafficIPoptions.pcap | diff - expected/expectedOutput2.txt

echo ""
echo "- - - TEST 3 - - - - -"
echo ""
../p1 inputs/trafficUdpTcp.pcap | diff - expected/expectedOutput3.txt
