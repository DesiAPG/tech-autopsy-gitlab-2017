package rules

import (
	"testing"

	"github.com/DesiAPG/tech-autopsy-gitlab-2017/internal/shell"
)

func match(line, cwd string) []string {
	ctx := Context{Cwd: cwd, ProtectedPaths: DefaultProtectedPaths, CriticalDirs: DefaultCriticalDirs, FullLine: line}
	var ids []string
	for _, c := range shell.Parse(line) {
		for _, r := range All() {
			if _, ok := r.Match(c, ctx); ok {
				ids = append(ids, r.ID)
			}
		}
	}
	return ids
}

func TestDestructive(t *testing.T) {
	tests := []struct{ line, cwd, rule string }{
		// The GitLab command, absolute and relative.
		{`sudo rm -rf /var/opt/gitlab/postgresql/data`, "", "rm-recursive-protected"},
		{`rm -rf data`, "/var/opt/gitlab/postgresql", "rm-recursive-protected"},
		{`rm -r -f /var/lib/postgresql/16/main`, "", "rm-recursive-protected"},
		{`rm --recursive --force /var/lib/mysql`, "", "rm-recursive-protected"},
		{`rm -rf /`, "", "rm-recursive-protected"},
		{`rm -rf /*`, "", "rm-recursive-protected"},
		{`rm -rf /etc`, "", "rm-recursive-protected"},
		{`rm -rf -- /data/pg`, "", "rm-recursive-protected"},
		{`find /var/lib/postgresql -name '*.wal' -delete`, "", "find-delete-protected"},
		{`find /data -type f -exec rm {} +`, "", "find-delete-protected"},
		{`dd if=/dev/zero of=/dev/nvme0n1 bs=1M`, "", "disk-wipe"},
		{`mkfs.ext4 /dev/sdb1`, "", "disk-wipe"},
		{`psql -c "DROP DATABASE gitlabhq_production"`, "", "sql-destructive"},
		{`gitlab-psql -c 'truncate table users'`, "", "sql-destructive"},
		{`echo "DELETE FROM users;" | psql prod`, "", "sql-destructive"},
		{`mysql -e "drop schema app"`, "", "sql-destructive"},
		{`dropdb gitlabhq_production`, "", "db-drop-tool"},
		{`redis-cli -h cache FLUSHALL`, "", "db-drop-tool"},
		{`mongosh --eval "db.dropDatabase()"`, "", "db-drop-tool"},
		{`kubectl delete ns payments`, "", "kubectl-delete-stateful"},
		{`kubectl -n db delete pvc/data-postgres-0`, "", "kubectl-delete-stateful"},
		{`kubectl delete pods --all`, "", "kubectl-delete-stateful"},
		{`helm uninstall postgres`, "", "helm-uninstall"},
		{`terraform destroy -auto-approve`, "", "terraform-destroy"},
		{`terraform apply -destroy`, "", "terraform-destroy"},
		{`aws rds delete-db-instance --db-instance-identifier prod`, "", "cloud-delete"},
		{`aws s3 rm s3://backups --recursive`, "", "cloud-delete"},
		{`aws s3 rb s3://backups --force`, "", "cloud-delete"},
		{`gcloud sql instances delete prod-db`, "", "cloud-delete"},
		{`docker volume rm pgdata`, "", "docker-volume-delete"},
		{`docker system prune -af --volumes`, "", "docker-volume-delete"},
		{`ssh db1 'rm -rf /data'`, "", ""}, // ssh itself: inner line is handled by guard
	}
	for _, tt := range tests {
		ids := match(tt.line, tt.cwd)
		if tt.rule == "" {
			continue
		}
		found := false
		for _, id := range ids {
			if id == tt.rule {
				found = true
			}
		}
		if !found {
			t.Errorf("%q (cwd %q): want rule %s, got %v", tt.line, tt.cwd, tt.rule, ids)
		}
	}
}

func TestHarmless(t *testing.T) {
	for _, line := range []string{
		`rm -rf ./build`,
		`rm -rf /tmp/cache`,
		`rm /var/opt/gitlab/postgresql/data/postmaster.pid`, // not recursive
		`rm -rf ~/scratch`,
		`rm -rf /home/duvan/project/node_modules`,
		`rm -rf /usr/local/share/app/cache`,
		`ls -la /var/opt/gitlab/postgresql/data`,
		`psql -c "DELETE FROM sessions WHERE expires_at < now()"`,
		`psql -c "SELECT count(*) FROM users"`,
		`echo "DROP DATABASE x"`, // no SQL client involved
		`kubectl delete pod web-7c9f`,
		`kubectl get ns`,
		`terraform plan`,
		`aws s3 rm s3://bucket/one-file.txt`,
		`aws rds describe-db-instances`,
		`docker volume ls`,
		`dd if=/dev/sda of=/tmp/disk.img`,
		`rm -rf data 2>/dev/null`,
	} {
		if ids := match(line, "/home/duvan"); len(ids) > 0 {
			t.Errorf("%q should be harmless, matched %v", line, ids)
		}
	}
}
