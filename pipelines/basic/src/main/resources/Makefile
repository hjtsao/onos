BMV2_CPU_PORT=255
BMV2_OPTIONS="-DTARGET_BMV2 -DCPU_PORT=${BMV2_CPU_PORT}"

all: basic int

basic: basic.p4
	p4c-bm2-ss --arch v1model -o p4c-out/bmv2/basic.json \
        ${BMV2_OPTIONS} \
		--p4runtime-files p4c-out/bmv2/basic_p4info.txt \
		basic.p4

int: int.p4
	p4c-bm2-ss --arch v1model -o p4c-out/bmv2/int.json \
        ${BMV2_OPTIONS} \
		--p4runtime-files p4c-out/bmv2/int_p4info.txt \
		int.p4

clean:
	rm -rf p4c-out/bmv2/*
