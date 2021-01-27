

#### step 01 - download file(s)

e.g. for a specific minute file run

```bash
gsutil cp gs://rbz-logs-ekreblaze/bqinsert/queue-in/compose/20210121T0608-bq_load* .
```
#### step 02 - split into 20K lines

```bash
for FI in *-bq_load*;
do
    echo $FI
    split -l 20000 $FI $FI.split. -da 4;
    rm $FI
done
```

#### step 03 - convert files into bulk inserts json

```bash
for FI in *-bq_load*.split.*;
do
    echo $FI
    /usr/bin/python3 convert.py < "$FI" > "bulk-$FI.json";
done
```

#### step 04 - insert into ES

```bash
for FI in bulk-*.json;
do
    echo $FI;
    curl -s -H "Content-Type: application/x-ndjson" -XPOST localhost:9200/_bulk --data-binary "@$FI";
done
```