package output

type outputtype int

const (
	output_txt outputtype = iota
	output_text
	output_tbl
	output_table
	output_json
	invalid
)

var nameToOutputtype = map[string]outputtype{
	"txt":   output_txt,
	"text":  output_text,
	"tbl":   output_tbl,
	"table": output_table,
	"json":  output_json,
}

func IsValid(output string) (bool, outputtype) {
	if o, contained := nameToOutputtype[output]; contained {
		return true, o
	}
	return false, invalid
}

func IsText(t outputtype) bool {
	switch t {
	case output_text, output_txt:
		return true
	default:
		return false
	}
}

func IsTable(t outputtype) bool {
	switch t {
	case output_tbl, output_table:
		return true
	default:
		return false
	}
}

func IsJson(t outputtype) bool {
	switch t {
	case output_json:
		return true
	default:
		return false
	}
}
