all:
	gcc -g -Wall mac_address.c print_helpers.c prober.c -o prober -lpcap
