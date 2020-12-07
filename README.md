# Description

Linux file access tracking tool that I wrote because I like file access tracking and
totally not because it was an interview task or something.

# Usage

## Dependencies

`libaudit` is required. `systemd` is not strictly necessary, but the end product is
meant to be run as a systemd service.

## Build

Checkout the git repo:

```
git clone https://github.com/lipk/dirwatch.git
cd dirwatch
git submodule update --init --recursive
```

Verify that the systemd units directory is located at `/lib/systemd/system` on your
system. If not, modify SYSTEMD_DIR in CMakeLists.txt accordingly.

Build dirwatch:

```
cd build
cmake ..
make
```

And install:

```
make install
```

## Configuration

The config file is installed at `/etc/config/dirwatch.json` by default. It looks like
this:

```
{
    "outputPath": "/var/log/dirwatch.log",
    "dirs": [
        {
            "path": "/home/lipk/dwtest"
        }
    ]
}
```

`outputPath` is the path to the log file. `dirs` are the directories you want to
watch for access. Enter large directories and infinite link-loops at your own peril.

## Run

Disable `auditd`, if installed:

```
systemctl disable auditd
```

Enable dirwatch:

```
systemctl enable dirwatch
systemctl start dirwatch
```

## Logs

Error logs are written to syslog (`/var/log/syslog`, most likely).

# Notes

## Known issues

* dirwatch uses filepaths as audit rule keys. There seems to be a limit on key
length, so this would likely be a problem for long paths.

* rm -r reports deletions on the wrong paths. This appears to be a bug in libaudit.

* The directory hierarchy is traversed recursively. Very deep or infinite hierarchies
will crash the program.

* libaudit is rather poorly documented, so there's some guesswork involved in the
interface. Some edge cases may not work as expected.

## Design choices

The whole audit subsystem appears to assume that only a single daemon will handle all
events. So ideally, dirwatch should be implemented as an auditd plugin rather than a
service by itself so that it doesn't prevent other auditing services from being used.
I decided to create a standalone service to minimize dependencies. The conversion
shouldn't be too difficult; `EventHandler::nextRecord` would need to parse messages
from stdin rather than `audit_get_reply`, but that's about it.

Error handling is not fleshed out. There's virtually no retry/fix logic and some
errors that might not actually be errors at all will be logged as such anyway.
Further thought and a more detailed specification would be needed to improve this.

Similarly, performance was not a main concern while developing dirwatch. I believe
the general design is not wasteful by nature, but some actual measurements on
realistic samples would be needed to determine what, if anything, needs to be
improved. Of particular concern are the number of watches and the amount of memory
they take.