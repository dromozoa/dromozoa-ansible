#! /bin/sh -e

source=$1
case x$source in
  x) exit 1;;
esac
shift

target=$1
case x$target in
  x) exit 1;;
esac
shift

echo "#! /usr/bin/env lua" >"$target"
for i in utf8 json shlex
do
  curl -fsL "https://github.com/dromozoa/dromozoa-$i/raw/master/dromozoa-$i.lua" >>"$target"
done
cat "$source" >>"$target"
chmod 755 "$target"
