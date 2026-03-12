set(src
  in_dnstap.c
  dnstap_parser.c
  dnstap_decode.c
  dnstap.pb-c.c
)

FLB_PLUGIN(in_dnstap "${src}" "")
