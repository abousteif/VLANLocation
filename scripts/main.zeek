#Scripts to use when you want to enrich conn log with location information for VLANs
#For Network locations, upload a file to the input framework of the sensor called localvlandef.db to assign addresses to names
#the format should be like this #fields<tab>vlanid<tab>name<carriagereturn>###<tab>Washington and so on

module T2T;

type Idx: record {
	vlanid: string;
};
type Val: record {
	name: string;
};

global privvlan: table[id] of string = table();

# label what we can
event connection_state_remove(c: connection)
	{
	if ( c$id$vlan in privvlan )
		c$conn$orig_cc = privvlan[c$id$vlan];
	}

event zeek_init()
	{
	Input::add_table([
		$source="localvlandef.db",
		$name="privvlan",
		$idx=Idx,
		$destination=privvlan,
		$val=Val,
		$mode=Input::REREAD,
		$want_record=F
	]);
	}
