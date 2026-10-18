# go-guard

**Bloquea comandos destructivos en servidores de producción hasta que un segundo ingeniero los apruebe.**

```text
$ sudo rm -rf /var/opt/gitlab/postgresql/data
× BLOQUEADO · go-guard
comando destructivo en entorno de producción
  regla:   rm-recursive-protected  (rm -r sobre /var/opt/gitlab/postgresql/data)
  entorno: host "db1.cluster.gitlab.com" es producción (db1)
→ requiere aprobación de un segundo ingeniero:
    go-guard approve -- sudo rm -rf /var/opt/gitlab/postgresql/data
  y luego: export GO_GUARD_APPROVAL=<token>
```

## Por qué existe

El 31 de enero de 2017, un ingeniero de GitLab intentaba resincronizar la réplica de PostgreSQL. Cansado, a altas horas, ejecutó `rm -rf` sobre el directorio de datos creyendo estar en **db2** (secundario). Estaba en **db1**, el primario. Cuando lo detuvo, de unos 300 GB quedaban unos 4.5 GB.

Al intentar restaurar descubrieron que **ninguno de sus cinco mecanismos de backup y replicación funcionaba de forma fiable**: `pg_dump` fallaba en silencio por una versión incompatible de PostgreSQL, los backups en S3 estaban vacíos, los snapshots de disco de Azure no estaban activos para los servidores de base de datos, la replicación estaba rota y las alertas por email de esos fallos eran rechazadas por DMARC. GitLab.com estuvo caído unas 18 horas y perdió unas 6 horas de datos de producción. Restauraron desde un snapshot LVM que alguien había hecho a mano 6 horas antes.

El error no fue del ingeniero, fue de la arquitectura: **un humano cansado nunca debería estar a un `Enter` de borrar producción.** go-guard pone ese `Enter` detrás de una segunda firma.

Post-mortem oficial: <https://about.gitlab.com/blog/2017/02/10/postmortem-of-database-outage-of-january-31/>

## Qué hace

1. **Entiende el comando.** Separa listas y pipelines (`;`, `&&`, `||`, `|`), quita envoltorios (`sudo`, `env`, `nohup`, `timeout`…), sigue los `cd` para resolver rutas relativas y entra en `bash -c '…'` y `ssh host '…'`.
2. **Detecta si es destructivo** con un catálogo de reglas (`go-guard rules`): `rm -r` sobre directorios de datos, `DROP`/`TRUNCATE`/`DELETE` sin `WHERE`, `dropdb`, `FLUSHALL`, `kubectl delete ns|pvc|sts|--all`, `helm uninstall`, `terraform destroy`, borrados de RDS, S3, EC2, Cloud SQL, volúmenes Docker, `dd`/`mkfs` sobre discos…
3. **Decide si es producción**, por dónde aterriza el comando: `GO_GUARD_ENV`, el hostname (patrones `prod`/`prd`/`production` o una lista explícita como `db1`, `db2`), el contexto de Kubernetes, el perfil de AWS y, en `ssh host '…'`, el host remoto.
4. **Bloquea** si es destructivo **y** es producción, salvo que haya una aprobación válida para **ese comando exacto**, firmada por **otra persona** y no caducada. Fuera de producción solo avisa.
5. **Audita** cada decisión destructiva en un log JSON (`~/.local/state/go-guard/audit.log`).

## Instalación

```bash
go install github.com/DesiAPG/tech-autopsy-gitlab-2017/cmd/go-guard@latest
```

O desde el código: `make build` (deja el binario en `bin/go-guard`). Requiere Go 1.24+ y no tiene dependencias externas.

### Integración con la shell

Con la integración activa, cada comando pasa por go-guard antes de ejecutarse.

```bash
# bash (~/.bashrc)
eval "$(go-guard hook bash)"

# zsh (~/.zshrc)
eval "$(go-guard hook zsh)"
```

En bash se usa `extdebug` + un trap `DEBUG`: si go-guard devuelve un código distinto de 0, bash **no ejecuta** el comando. En zsh se envuelve `accept-line`: la línea bloqueada queda en el historial para poder aprobarla y repetirla.

### Uso explícito (scripts, CI, runbooks)

```bash
go-guard check -- terraform destroy          # exit 0 = permitido, 3 = bloqueado
go-guard check --json -- psql -c "DROP DATABASE app"
go-guard run -- kubectl delete ns payments   # evalúa y, si procede, ejecuta
go-guard env                                 # ¿este entorno cuenta como producción?
```

## Flujo de aprobación (regla de cuatro ojos)

Las dos personas comparten `GO_GUARD_SECRET`, que viene de tu gestor de secretos.

```bash
# Alice revisa el comando y lo aprueba durante 15 minutos
alice$ go-guard approve --ttl 15m -- sudo rm -rf /var/opt/gitlab/postgresql/data
gg1.eyJjIjoi…

# Bob lo ejecuta con ese token
bob$ export GO_GUARD_APPROVAL=gg1.eyJjIjoi…
bob$ sudo rm -rf /var/opt/gitlab/postgresql/data
✔ APROBADO · go-guard aprobado por alice hasta 2026-10-18T04:15:00Z
```

El token:
- cubre **solo ese comando** (se compara un SHA-256 del comando normalizado);
- **caduca** (por defecto 15 min, máximo 24 h);
- **no sirve a quien lo firmó** (`no puedes aprobar tu propio comando`), salvo que actives `allow_self_approval`;
- va firmado con HMAC-SHA256, así que no se puede editar.

## Configuración

Es opcional. Por defecto el fichero está en `~/.config/go-guard/config.json`, o donde indique `GO_GUARD_CONFIG`. Todas las listas **amplían** los valores por defecto. Hay un ejemplo en [`examples/config.json`](examples/config.json).

```json
{
  "production_hosts": ["db1", "db2", "gitlab-db*"],
  "production_patterns": ["(?i)^payments-"],
  "protected_paths": ["/srv/gitlab/uploads"],
  "disabled_rules": [],
  "allow_self_approval": false
}
```

Si el config es inválido, go-guard **falla cerrado**: bloquea.

| Variable | Uso |
| --- | --- |
| `GO_GUARD_ENV` | `prod`/`production` fuerza producción; `dev`/`staging`/`test`/`local` lo descarta |
| `GO_GUARD_APPROVAL` | token emitido por `go-guard approve` |
| `GO_GUARD_SECRET` | secreto compartido para firmar y verificar aprobaciones |
| `GO_GUARD_CONFIG` | ruta del config |
| `GO_GUARD_AUDIT_LOG` | ruta del log de auditoría, u `off` |
| `NO_COLOR` | desactiva colores |

## Límites (léelos)

go-guard es un **cinturón de seguridad, no una frontera de seguridad.** Frena el error humano, el `Enter` cansado de las 23:00, pero no detiene a quien quiera saltárselo: puede desactivar el hook, llamar a `/bin/rm` desde un script o escribir `$VAR` donde bash no la expande en `$BASH_COMMAND`.

La protección real es de arquitectura, y go-guard la complementa:

- **Bastion host** con MFA y sesiones auditadas: nadie hace SSH directo a producción.
- **Mínimo privilegio**: el usuario de operaciones no puede borrar el directorio de datos; IAM y roles de base de datos sin `DROP` para personas.
- **Infraestructura inmutable**: los cambios a producción solo entran por pipeline (IaC + revisión), no a mano.
- **Backups que se prueban**: restaurar es un job programado con alerta si falla, no un supuesto. Ese fue el verdadero fallo de 2017.

## Desarrollo

```bash
make test    # go test -race ./...
make vet     # go vet + gofmt
make build
```

Estructura:

```
cmd/go-guard/        CLI (check, run, approve, hook, rules, env)
internal/shell/      parser de líneas de comando (listas, pipelines, sudo, ssh, bash -c)
internal/rules/      catálogo de reglas destructivas
internal/env/        detección de producción
internal/approval/   tokens de aprobación HMAC
internal/guard/      decisión final
internal/audit/      log JSON de auditoría
internal/config/     config JSON opcional
```

---

Hecho por **Duván Marín**, ingeniero de software backend. Escribo post-mortems técnicos de por qué fallan los sistemas en producción.

Licencia MIT.
