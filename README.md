# prune-artifacts

GitHub action to delete old/large artifacts from a repo. Also a vehicle for experimenting with writing a GitHub action
in Kotlin.

This project builds with Gradle, just use `./gradlew build` as normal.

A packaged distributable is written into `dist` by running `./gradlew package`.

## Using the action

An example:

```yaml
permissions:
  contents: read
  actions: write

jobs:
  prune-artifacts:
    runs-on: ubuntu-latest
    steps:
      - name: Prune artifacts
        uses: araqnid/prune-artifacts@v1
        with:
          min-age: 3d
          min-size: 1Mb
          name: big_artifact
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```
