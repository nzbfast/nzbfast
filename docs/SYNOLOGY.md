# nzbfast on a Synology NAS

nzbfast runs on Synology DSM 7 as a Docker container through **Container
Manager** (Package Center → *Container Manager*; on DSM 6 the same app is
called *Docker*). One container gives you the full web dashboard, the
SABnzbd/NZBGet-compatible API for Sonarr/Radarr, and the built-in indexer.

The image is multi-arch, so it runs on both Intel and ARM (Realtek/RTD,
Annapurna) Synology models with no change. It's published to two
registries that serve the **identical** image - `nzbfast/nzbfast` on
Docker Hub (this is the one Container Manager can *search* for) and
`ghcr.io/nzbfast/nzbfast` on GitHub. Use whichever you prefer; the guide
uses the Docker Hub name.

There are two ways in. **Route A is the one to take** - a single compose
file, which is also the only way to have the container keep itself up to
date. Route B is search-and-click, with no text file at all, at the cost
of updating by hand.

---

## Before you start: make three folders (1 minute, no SSH)

In **File Station**, create a folder for nzbfast - `/docker/nzbfast` is
the convention - and then three folders **inside** it, named exactly:

```
config      settings + index database
downloads   finished files
watch       drop an .nzb here and it downloads
```

That is the whole preparation, and it replaces the SSH session that used
to be needed here.

> **Running Sonarr or Radarr on this NAS? Read this first, not later.**
> On a DiskStation `/docker` and your media library are almost always
> different shared folders, and that one fact decides whether every import
> is instant or is a full copy of a 5-50 GB release. Put downloads under
> the *same* shared folder as the library instead - see
> [Sonarr and Radarr: where downloads have to live](#sonarr-and-radarr-where-downloads-have-to-live)
> below and use those folders in place of `downloads` throughout. It is
> two minutes now and a rebuild later.

**Why it matters.** nzbfast writes your downloads as a real user so the
files belong to *you* rather than to root, and it works out which user
from the folders it is given: folders you make in File Station belong to
you, so it adopts your user and group automatically.

If you skip this, Docker creates those folders itself and they belong to
root. nzbfast then has nothing to read an owner from and falls back to
uid 1000 - a user your NAS does not know - so your downloads arrive
owned by nobody you can see, and File Station will not let you move or
delete them. A container cannot see the folder *above* a mount, so this
is not something it can work out for itself.

If you would rather not make the folders, or you want the files owned by
somebody else, the compose file has commented-out `PUID`/`PGID` lines and
the old `id your_dsm_username` method still works.

> **On 1.0.11 and earlier**, only the *user* is picked up this way, not the
> group: files come out owned by your user but with a group matching it
> rather than the folder's. You own them either way, so File Station can
> still manage them. Adopting the group needs 1.0.12 or later, or set
> `PGID` explicitly until then.

---

## Route A - Container Manager Project (one compose file)

One file you can back up, re-use, and update with a single click. Take
this route if you want nzbfast to keep itself current.

**The quickest version:** download
[`docker-compose.yml`](https://nzbfast.github.io/nzbfast/nzbfast-synology.yml),
put it in `/docker/nzbfast` with File Station, and create a Project
pointing at that folder. **Nothing in the file needs editing.** The steps
below are the same thing done by hand.

1. Make the folders, if you have not already: `/docker/nzbfast` with
   `config`, `downloads` and `watch` inside it.
2. Container Manager → **Project** → **Create**.
   - **Project name:** `nzbfast`
   - **Path:** `/docker/nzbfast`
   - **Source:** *Create docker-compose.yml* and paste:

   ```yaml
   services:
     nzbfast:
       image: nzbfast/nzbfast:latest
       container_name: nzbfast
       restart: unless-stopped
       ports:
         - "6789:6789"
       volumes:
         - ./config:/config          # settings + index database
         - ./downloads:/downloads    # finished files - but see below if
                                     # you run Sonarr or Radarr
         - ./watch:/watch            # drop an .nzb here to auto-download
       # No PUID/PGID needed: nzbfast adopts the owner and group of the
       # folders you made above. No TZ either - times are stored as UTC
       # and shown in your browser's timezone.
       # Takes away powers the container has by default and does not use.
       # The five it does need are added back by name: without them it
       # cannot hand your folders to your DSM user and will not start.
       cap_drop: [ALL]
       cap_add: [CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID]
       security_opt: [no-new-privileges:true]

     # Optional: checks nightly for a newer nzbfast image and recreates
     # the container when one ships. Needs the Docker socket; delete this
     # service to update by hand, or on a DSM schedule instead.
     watchtower:
       image: nickfedor/watchtower
       container_name: nzbfast-watchtower
       restart: unless-stopped
       environment:
         - TZ=Etc/UTC   # your timezone, so the schedule below is your 04:00
       volumes:
         - /var/run/docker.sock:/var/run/docker.sock
       command: --cleanup --schedule "0 0 4 * * *" nzbfast   # daily 04:00, nzbfast only
   ```

3. Finish the wizard - Container Manager pulls the images and starts
   them. Then jump to [First run](#first-run---add-your-provider).

The one value worth changing is `TZ` on the **watchtower** service, and
only so that "04:00" means 04:00 where you live. It does nothing on the
nzbfast container, which is why it is not there.

**About that last service.** Watchtower is what keeps nzbfast current,
and it needs the Docker socket to recreate containers. Mounting
`/var/run/docker.sock` gives that container root-equivalent control of
your NAS, so it is a real trade: convenience against handing one
container broad power. If you would rather not make it, delete the
`watchtower` block and take the scheduled-task route below instead. As
written it is scoped to the `nzbfast` container by the name at the end of
the `command` line, so it will never touch your other containers.

### Auto-update without the Docker socket

DSM can do the same job on a schedule, and nothing needs the socket
mounted. Delete the `watchtower` service from the compose file, then:

1. Control Panel → **Task Scheduler** → **Create** → **Scheduled Task**
   → **User-defined script**.
2. **General:** name it something like `nzbfast update`, and set **User**
   to `root` (Docker commands need it).
3. **Schedule:** daily, at a quiet hour.
4. **Task Settings → Run command:**

   ```sh
   cd /volume1/docker/nzbfast && docker compose pull && docker compose up -d
   ```

   Adjust the path to your project folder. On DSM 7.1 and older the
   command is `docker-compose` (with the hyphen) rather than
   `docker compose`.

The trade here runs the other way: the task itself runs as root, but
nothing gains standing access to the Docker socket, and you can read
exactly what it does.

---

## Route B - Container Manager (search & click)

No text files at all. The trade-off: a container built this way **cannot
auto-update**, because Container Manager's volume picker only browses
shared folders and so cannot mount the Docker socket that Watchtower
needs. You update it by hand, a few clicks each release.

1. **Make the folders** - the same three as above, if you have not
   already:

   ```
   /docker/nzbfast/config       ← settings + index database
   /docker/nzbfast/downloads    ← finished files land here
   /docker/nzbfast/watch        ← drop an .nzb here to auto-download it
   ```

   With Sonarr or Radarr on this NAS, downloads belong somewhere else -
   see [Sonarr and Radarr: where downloads have to live](#sonarr-and-radarr-where-downloads-have-to-live).

2. **Get the image.** Container Manager → **Registry** → search
   **`nzbfast`** → select **`nzbfast/nzbfast`** → **Download** → tag
   **`latest`**.

3. **Create the container.** Container Manager → **Image** → select
   `nzbfast/nzbfast:latest` → **Run**. In the wizard:

   - **General:** turn on *Enable auto-restart*.
   - **Port Settings:** map **Local port `6789` → Container port `6789`**
     (change the Local port only if 6789 is already taken on your NAS).
   - **Volume Settings - add three folder mounts:**

     | Folder (on your NAS)          | Mount path in container |
     | ----------------------------- | ----------------------- |
     | `/docker/nzbfast/config`      | `/config`               |
     | `/docker/nzbfast/downloads`   | `/downloads`            |
     | `/docker/nzbfast/watch`       | `/watch`                |

     Running Sonarr or Radarr? Replace the `downloads` row per
     [Sonarr and Radarr: where downloads have to live](#sonarr-and-radarr-where-downloads-have-to-live).

   - **Environment:** nothing to add. Because you made the folders
     yourself, nzbfast takes its user and group from them. `TZ` is not
     needed either - times are stored as UTC and displayed in your
     browser's timezone.

4. **Run it**, then jump to [First run](#first-run---add-your-provider).

---

## First run - add your provider

There is **no config file to edit.** Open the dashboard:

```
http://YOUR_NAS_IP:6789
```

The page asks for an **API key** before it shows you anything. nzbfast
generated one for itself when the container first started, so that your
dashboard is not open to everything on your network. Two places to find
it:

- **Container Manager → your container → Log.** It is printed once, near
  the top of the first start, on the line beginning `API key:`.
- **File Station → `/docker/nzbfast/config/apikey`** - the same value, kept
  so it survives restarts and image updates.

Paste it in once; the browser remembers it. Keep it to hand, because
Sonarr, Radarr and phone apps need the same value. To pick your own
instead, set `NZBFAST_APIKEY` on the container, or change it later in
Settings → Security.

Then a **Welcome** panel asks for your Usenet server. Enter the
host, username, password and (optionally) connection count from your
provider's welcome email, and click save. It applies immediately - no
restart. That's it; drop an `.nzb` on the dashboard, or into the `watch`
folder, and it downloads.

---

## Sonarr and Radarr: where downloads have to live

Skip this if you do not run them.

When an \*arr imports a finished download it either **renames** the files
into your library, which is instant and costs no extra disk, or **copies**
them and deletes the original, which on NAS hardware is the slowest thing
in the chain. Which one you get is decided entirely by where the downloads
sat, and Docker decides it more bluntly than the disk does: two separate
mounts look like two filesystems to a container even when they are one
volume underneath.

So put both under one shared folder. If your library lives in a shared
folder called `data`, make the tree:

```
/volume1/data/usenet     ← nzbfast downloads here
/volume1/data/media      ← your Sonarr/Radarr library
```

Then mount it into nzbfast **at the same path on both sides**:

| Folder (on your NAS) | Mount path in container |
| -------------------- | ----------------------- |
| `/volume1/data/usenet` | `/volume1/data/usenet`  |

and add one environment variable, `NZBFAST_OUT` = `/volume1/data/usenet`.
In the compose file that is `- /volume1/data/usenet:/volume1/data/usenet`
under `volumes:` in place of the downloads line, and
`- NZBFAST_OUT=/volume1/data/usenet` under `environment:`.

**Both halves matter.** The shared root is what makes the import a rename.
The identical path is what makes it happen at all: nzbfast tells your \*arr
where a finished job is, so that path has to mean the same thing inside
their container as it does inside nzbfast's. Map it somewhere else and the
download simply sits in the queue while the \*arr reports a remote path
mapping error, with nothing actually wrong with the files.

Give nzbfast `usenet` only, not the whole `data` folder. It has no business
in your library, and the rename still works, because it is your \*arr that
moves the files and it can see both sides.

There is **no `incomplete` folder** to make. SABnzbd needs one because it
writes there and moves everything across when a job finishes. nzbfast
writes at the final path from the first article on, so there is nothing to
move - a SAB migrant has two filesystem boundaries to get right here and
you have exactly one. The flip side: a folder holding finished downloads
also holds in-progress ones while they run. That is harmless, because the
\*arrs import on the API's job state rather than by watching the folder.

If you would rather follow a guide written for DSM specifically, TRaSH
keep one: <https://trash-guides.info/Hardlinks/How-to-setup-for/Synology/>

---

## Connecting Sonarr / Radarr / Prowlarr

nzbfast speaks the SABnzbd API. In your \*arr app, add a **SABnzbd**
download client:

- **Host:** your NAS IP  **Port:** `6789`
- **API Key:** the same key you typed into the dashboard - the generated
  one from [First run](#first-run---add-your-provider), or whatever you set
  as `NZBFAST_APIKEY` on the container (Environment tab, or the commented
  line in the compose file).

It also exposes the NZBGet JSON-RPC API for NZBGet remotes such as
LunaSea; nzb360 connects with the same SABnzbd settings as the *arrs.

---

## Updating

The **image is the update channel** - nzbfast in a container never swaps
its own binary (it's a managed/"bundled" install), so you move it forward
by pulling a newer image. Your `config` and `downloads` survive, because
they live in your NAS folders and not inside the container.

- **Automatically**, if you took Route A and kept the `watchtower`
  service: nothing to do. It checks nightly at 04:00 and recreates the
  container when a new version ships.
- **Automatically, without the Docker socket:** the DSM scheduled task
  described under
  [Auto-update without the Docker socket](#auto-update-without-the-docker-socket).
- **By hand, in a Project:** Container Manager → **Project** → `nzbfast`
  → **Stop**, then **Build** (this re-pulls `latest`), then **Start**.
- **By hand, Route B:** Container Manager → **Registry** → re-download
  the `latest` tag → then **Container** → stop nzbfast → **Action →
  Reset/Clear** to recreate it on the new image.

**Check your image tag first.** All of the above assumes your container
is on `nzbfast/nzbfast:latest`. If it is pinned to a version, say
`:1.0.3`, then neither Watchtower nor a re-pull will ever move it: both
fetch the tag the container was created with. Container Manager →
**Container** → **Details** shows which one you have.

---

## Troubleshooting

- **It will not start after an update, or Container Manager says
  "stopped unexpectedly"** - the container prints the reason and exits,
  so the reason is in its log, not in DSM's. Container Manager →
  **Container** → `nzbfast` → **Details** → the **Log** tab. DSM's own
  **Log** page in the left-hand menu is a different thing: it records who
  pressed start and stop, and will never show you why a container died.
  Over SSH the same thing, more reliably:

  ```sh
  sudo docker logs --tail 50 nzbfast
  ```

  A container that quits a second or two after starting, over and over,
  is nearly always refusing on purpose rather than crashing, and the log
  says which case it is and how to fix it.
- **Downloads folder "permission denied" / files owned by root** - your
  `PUID`/`PGID` don't match the folder's owner. Re-check them with
  `id your_dsm_username` and fix the Environment values. This is the
  single most common issue.
- **Can't reach the dashboard** - confirm the container is running and
  that you mapped the port. If something else on the NAS uses 6789,
  remap the *local* side (e.g. `6889:6789`) and browse to `:6889`.
- **`nzbfast` doesn't appear in Registry search** - make sure you're
  searching the **Registry** tab (not *Image*), and that your NAS has
  internet access. You can also pull it by exact name
  `nzbfast/nzbfast`.
- **Nothing downloads** - open the dashboard; if the Welcome panel is
  still showing, the provider hasn't been saved yet.
- **Auto-update never fires** - check the container is on the `latest`
  tag rather than a pinned version, and that the schedule ran in your
  timezone (set `TZ` on the watchtower service, or `0 0 4 * * *` means
  04:00 UTC). `sudo docker logs nzbfast-watchtower` shows its next run.

---

## Which Synology models?

Any DSM 7 model with Container Manager (and most DSM 6 models with
Docker). Both Intel (x86-64) and ARM64 units are covered by the same
multi-arch image. Very low-end ARMv7/32-bit models are not supported -
they're below the workload nzbfast is built for.
