## A Binary C++ Disassembler

### Building

After cloning, initialize the submodules:

```
$ git submodule init
$ git submodule update --recursive
```

Set a `ABCD_SOURCE_PATH` environment variable for use during the
rest of the build:

```
$ export ABCD_SOURCE_PATH=`pwd`
```

Next, create a build directory. `cd` in to that build directory and
create/set a `ABCD_BUILD_PATH` environment variable for use during the
rest of the build:

```
$ export ABCD_BUILD_PATH=`pwd`
```

Now, from the `ABCD_BUILD_PATH` directory, run `cmake`:

```
$ cmake ${ABCD_SOURCE_PATH}
```

And, finally, just `make`:

```
$ make
```

### Running

From the *build* directory you created/used above, you can run the disassembler:

```
$ ./abcd
```
