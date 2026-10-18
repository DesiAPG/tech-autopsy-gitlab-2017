package shell

import (
	"reflect"
	"testing"
)

func TestTokenize(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{`rm -rf /data`, []string{"rm", "-rf", "/data"}},
		{`psql -c "DROP DATABASE x"`, []string{"psql", "-c", "DROP DATABASE x"}},
		{`echo 'a b' c\ d`, []string{"echo", "a b", "c d"}},
		{`  spaced   out  `, []string{"spaced", "out"}},
	}
	for _, tt := range tests {
		if got := Tokenize(tt.in); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("Tokenize(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseSplitsListsAndPipelines(t *testing.T) {
	cmds := Parse(`cd /var/opt/gitlab && sudo rm -rf data; echo "a;b" | wc -l`)
	var names []string
	for _, c := range cmds {
		names = append(names, c.Name())
	}
	want := []string{"cd", "rm", "echo", "wc"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("names = %q, want %q", names, want)
	}
	if got := cmds[2].Argv[1]; got != "a;b" {
		t.Errorf("quoted ; must not split: got %q", got)
	}
}

func TestStripWrappers(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{`sudo rm -rf /x`, "rm"},
		{`sudo -u postgres -H rm -rf /x`, "rm"},
		{`env PGHOST=db1 FOO=bar dropdb gitlab`, "dropdb"},
		{`LANG=C nohup nice -n 10 time rm -rf /x`, "rm"},
		{`timeout -s KILL 30 terraform destroy`, "terraform"},
		{`/usr/bin/sudo /bin/rm -rf /x`, "rm"},
	}
	for _, tt := range tests {
		c := Parse(tt.in)
		if len(c) != 1 || c[0].Name() != tt.want {
			t.Errorf("Parse(%q) program = %v, want %q", tt.in, c, tt.want)
		}
	}
}

func TestUnwrap(t *testing.T) {
	n, ok := Unwrap(Parse(`ssh -p 2222 -i key admin@db1.cluster.gitlab.com 'sudo rm -rf /var/opt/gitlab/postgresql/data'`)[0])
	if !ok || n.Host != "db1.cluster.gitlab.com" || n.Line != "sudo rm -rf /var/opt/gitlab/postgresql/data" {
		t.Fatalf("ssh unwrap = %+v, %v", n, ok)
	}
	n, ok = Unwrap(Parse(`bash -lc "rm -rf /data"`)[0])
	if !ok || n.Host != "" || n.Line != "rm -rf /data" {
		t.Fatalf("bash -c unwrap = %+v, %v", n, ok)
	}
	if _, ok := Unwrap(Parse(`ssh db1`)[0]); ok {
		t.Error("interactive ssh has no inner command")
	}
}
