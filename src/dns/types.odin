package dns

MAX_LABEL_LEN :: 63
MAX_NAME_WIRE :: 255
MAX_UDP_SIZE :: 512
MAX_MESSAGE :: 65535
HEADER_SIZE :: 12

Type :: enum u16 {
	None       = 0,
	A          = 1,
	NS         = 2,
	MD         = 3,
	MF         = 4,
	CNAME      = 5,
	SOA        = 6,
	MB         = 7,
	MG         = 8,
	MR         = 9,
	NULL       = 10,
	WKS        = 11,
	PTR        = 12,
	HINFO      = 13,
	MINFO      = 14,
	MX         = 15,
	TXT        = 16,
	RP         = 17,
	AFSDB      = 18,
	X25        = 19,
	ISDN       = 20,
	RT         = 21,
	NSAP       = 22,
	NSAP_PTR   = 23,
	SIG        = 24,
	KEY        = 25,
	PX         = 26,
	GPOS       = 27,
	AAAA       = 28,
	LOC        = 29,
	NXT        = 30,
	EID        = 31,
	NIMLOC     = 32,
	SRV        = 33,
	ATMA       = 34,
	NAPTR      = 35,
	KX         = 36,
	CERT       = 37,
	A6         = 38,
	DNAME      = 39,
	SINK       = 40,
	OPT        = 41,
	APL        = 42,
	DS         = 43,
	SSHFP      = 44,
	IPSECKEY   = 45,
	RRSIG      = 46,
	NSEC       = 47,
	DNSKEY     = 48,
	DHCID      = 49,
	NSEC3      = 50,
	NSEC3PARAM = 51,
	TLSA       = 52,
	SMIMEA     = 53,
	HIP        = 55,
	NINFO      = 56,
	RKEY       = 57,
	TALINK     = 58,
	CDS        = 59,
	CDNSKEY    = 60,
	OPENPGPKEY = 61,
	CSYNC      = 62,
	ZONEMD     = 63,
	SVCB       = 64,
	HTTPS      = 65,
	DSYNC      = 66,
	SPF        = 99,
	UINFO      = 100,
	UID        = 101,
	GID        = 102,
	UNSPEC     = 103,
	NID        = 104,
	L32        = 105,
	L64        = 106,
	LP         = 107,
	EUI48      = 108,
	EUI64      = 109,
	NXNAME     = 128,
	TKEY       = 249,
	TSIG       = 250,
	IXFR       = 251,
	AXFR       = 252,
	MAILB      = 253,
	MAILA      = 254,
	ANY        = 255,
	URI        = 256,
	CAA        = 257,
	AVC        = 258,
	DOA        = 259,
	AMTRELAY   = 260,
	RESINFO    = 261,
	TA         = 32768,
	DLV        = 32769,
}

Class :: enum u16 {
	IN   = 1,
	CS   = 2,
	CH   = 3,
	HS   = 4,
	NONE = 254,
	ANY  = 255,
}

Opcode :: enum u8 {
	Query  = 0,
	IQuery = 1,
	Status = 2,
	Notify = 4,
	Update = 5,
	DSO    = 6,
}

// Only the 4 low bits live in the header; EDNS0 supplies the upper 8.
Rcode :: enum u16 {
	No_Error   = 0,
	Form_Err   = 1,
	Serv_Fail  = 2,
	NX_Domain  = 3,
	Not_Impl   = 4,
	Refused    = 5,
	YX_Domain  = 6,
	YX_RRSet   = 7,
	NX_RRSet   = 8,
	Not_Auth   = 9,
	Not_Zone   = 10,
	DSO_Type_NI = 11,
	Bad_Vers   = 16, // also BADSIG; requires an OPT record to transmit
	Bad_Key    = 17,
	Bad_Time   = 18,
	Bad_Mode   = 19,
	Bad_Name   = 20,
	Bad_Alg    = 21,
	Bad_Trunc  = 22,
	Bad_Cookie = 23,
}

// Odin bit_fields pack from the least significant bit, so the declaration order
// here is the reverse of how RFC 1035 draws the header's second u16.
Flags :: bit_field u16 {
	rcode:  u8     | 4,
	cd:     bool   | 1,
	ad:     bool   | 1,
	z:      bool   | 1,
	ra:     bool   | 1,
	rd:     bool   | 1,
	tc:     bool   | 1,
	aa:     bool   | 1,
	opcode: Opcode | 4,
	qr:     bool   | 1,
}

Question :: struct {
	name:  string,
	type:  Type,
	class: Class,
}

Record :: struct {
	name:  string,
	type:  Type,
	class: Class,
	ttl:   u32,
	data:  Record_Data,
}

Record_Data :: union {
	Rdata_A,
	Rdata_AAAA,
	Rdata_Name,
	Rdata_SOA,
	Rdata_MX,
	Rdata_TXT,
	Rdata_SRV,
	Rdata_CAA,
	Rdata_OPT,
	Rdata_SVCB,
	Rdata_Raw,
}

Rdata_A :: struct {
	addr: [4]u8,
}

Rdata_AAAA :: struct {
	addr: [16]u8,
}

// CNAME, NS, PTR, DNAME, MB, MG, MR: a single domain name.
Rdata_Name :: struct {
	name: string,
}

Rdata_SOA :: struct {
	ns:      string,
	mbox:    string,
	serial:  u32,
	refresh: u32,
	retry:   u32,
	expire:  u32,
	minimum: u32,
}

Rdata_MX :: struct {
	preference: u16,
	exchange:   string,
}

Rdata_TXT :: struct {
	// Each element is one <character-string>; contents may be arbitrary bytes.
	strings: []string,
}

Rdata_SRV :: struct {
	priority: u16,
	weight:   u16,
	port:     u16,
	target:   string,
}

Rdata_CAA :: struct {
	flags: u8,
	tag:   string,
	value: string,
}

EDNS_Option :: struct {
	code: u16,
	data: []u8,
}

Rdata_OPT :: struct {
	options: []EDNS_Option,
}

Rdata_SVCB :: struct {
	priority: u16,
	target:   string,
	params:   []u8,
}

// Anything we do not model natively (RFC 3597 unknown-RR handling).
Rdata_Raw :: struct {
	data: []u8,
}

Message :: struct {
	id:         u16,
	flags:      Flags,
	question:   []Question,
	answer:     []Record,
	authority:  []Record,
	additional: []Record,
}

EDNS_Option_Code :: enum u16 {
	LLQ           = 1,
	NSID          = 3,
	DAU           = 5,
	DHU           = 6,
	N3U           = 7,
	Client_Subnet = 8,
	Expire        = 9,
	Cookie        = 10,
	TCP_Keepalive = 11,
	Padding       = 12,
	Chain         = 13,
	Key_Tag       = 14,
	Ext_Error     = 15,
}

// Name types that may legally appear compressed inside RDATA. New types are
// forbidden from using compression (RFC 3597), so we keep this list closed.
rdata_has_compressible_name :: proc "contextless" (t: Type) -> bool {
	#partial switch t {
	case .NS, .MD, .MF, .CNAME, .SOA, .MB, .MG, .MR, .PTR, .MINFO, .MX, .RP, .AFSDB, .RT, .PX, .NXT, .SIG, .NAPTR, .KX, .SRV, .A6, .DNAME:
		return true
	}
	return false
}

type_name :: proc(t: Type) -> string {
	#partial switch t {
	case .A:     return "A"
	case .NS:    return "NS"
	case .CNAME: return "CNAME"
	case .SOA:   return "SOA"
	case .PTR:   return "PTR"
	case .MX:    return "MX"
	case .TXT:   return "TXT"
	case .AAAA:  return "AAAA"
	case .SRV:   return "SRV"
	case .NAPTR: return "NAPTR"
	case .OPT:   return "OPT"
	case .DS:    return "DS"
	case .SSHFP: return "SSHFP"
	case .RRSIG: return "RRSIG"
	case .NSEC:  return "NSEC"
	case .DNSKEY:return "DNSKEY"
	case .NSEC3: return "NSEC3"
	case .TLSA:  return "TLSA"
	case .SVCB:  return "SVCB"
	case .HTTPS: return "HTTPS"
	case .CAA:   return "CAA"
	case .ANY:   return "ANY"
	case .AXFR:  return "AXFR"
	case .IXFR:  return "IXFR"
	case .DNAME: return "DNAME"
	case .URI:   return "URI"
	}
	return "TYPE?"
}
