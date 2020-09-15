Task Detector
------

Schedsnoop is a tool that traces the related schedule events of a specified task, e.g. the migration, sched in/out, wakeup and sleep/block. It will record the preemption information during tracing and output a report at the end to find out who has stolen the CPU for the most.

By execute command 'schedsnoop -t 4314', we continually trace the schedule events related to 'test' and finally output a report to show the top 10 processes that have preempted our target task (sorted by average preemption time):

```Shell
# ./schedsnoop -t 26371
Start tracing schedule events related to tid 26371
Press CTRL+C or wait until target exits to see report

Preemption Report:
CPU  TID    COMM                          Count  Avg       Longest   
2    2487   gsd-color                     1      139us     139us     
2    3241   gmain                         8      44us      92us      
2    0      swapper/2                     5      33us      38us      
2    1546   crond                         1      30us      30us      
2    697    kworker/2:1H                  11     13us      40us      
2    2798   JS Helper                     1      10us      10us      
2    24667  kworker/2:1                   8      8487ns    18us      
2    20     migration/2                   8      3475ns    4133ns    
2    1297   xfsaild/dm-2                  2      3149ns    3206ns    
```

It can also tracing the syscall by append options -s, which will output a syscall report at the end.

```Shell
# ./schedsnoop -t 26371 -s
Start tracing schedule events related to tid 26371(include SYSCALL)
Press CTRL+C or wait until target exits to see report

Preemption Report:
CPU  TID    COMM                          Count  Avg       Longest   
3    704    kworker/3:1H                  5      88us      240us     
3    3236   gmain                         4      59us      106us     
3    0      swapper/3                     3      58us      126us     
3    3764   kworker/3:1                   6      6359ns    17us      
3    25     migration/3                   5      2134ns    2249ns    

SYSCALL Report:
CPU  TID    SYSCALL                       Count  Avg       Longest   
3    3236   gmain[7:poll]                 3      6666ms    8000ms    
3    26371  test[35:nanosleep]            3      2003ms    2008ms    
3    26371  test[1:write]                 7      27us      68us      
3    3236   gmain[254:inotify_add_watch]  32     3867ns    64us      
```

With log option -l, it will print each related events synchronously with human-readable format, which could be more helpful on debugging the competition on CPU resource. If syscall option -s is enabled, it will also print related syscall events. Enabling debug option -d additionally could print raw timestamp instead of local time.

```Shell
# ./schedsnoop -t 26371 -l
Start tracing schedule events related to tid 26371
Press CTRL+C or wait until target exits to see report
----------------------------
21:29:20.556477     CPU=5      TID=26371  COMM=test                ENQUEUE                                               
21:29:20.556509     CPU=5      TID=0      COMM=swapper/5           PREEMPTED                            32us             
21:29:20.556514     CPU=5      TID=26371  COMM=test                EXECUTE AFTER WAITED                 37us             
21:29:24.366207     CPU=5      TID=26371  COMM=test                WAIT AFTER EXECUTED                  3809ms           
21:29:24.366212     CPU=5      TID=35     COMM=migration/5         PREEMPT                                               
21:29:24.366223     CPU=5      TID=35     COMM=migration/5         DEQUEUE AFTER PREEMPTED              10us             
21:29:24.366241     CPU=5      TID=26371  COMM=test                EXECUTE AFTER WAITED                 34us             
21:29:25.736573     CPU=5      TID=26371  COMM=test                DEQUEUE AFTER EXECUTED               1370ms           
...
``` 

Schedsnoop is now able to trace all threads in the specific process simultaneously with option -p.

```Shell
# ./schedsnoop -p 4292
Start tracing schedule events related to pid 4292
Press CTRL+C or wait until target exits to see reports

Preemption Report:
Target task 4293
CPU  TID    COMM                          Count  Avg       Longest   
5    0      swapper/5                     1      64us      64us      
1    2738   wpa_supplicant                1      18us      18us      
1    3898   kworker/1:10                  22     11us      24us      
0    0      swapper/0                     1      8931ns    8931ns    

Target task 4296
CPU  TID    COMM                          Count  Avg       Longest   
5    0      swapper/5                     1      64us      64us      
4    3278   gmain                         1      57us      57us      
4    3238   pool                          3      38us      47us      
4    3137   sssd_kcm                      1      20us      20us      
0    0      swapper/0                     1      8931ns    8931ns    
4    4317   kworker/4:11                  3      4707ns    5479ns    

Target task 4294
CPU  TID    COMM                          Count  Avg       Longest   
0    2745   gsd-color                     1      174us     174us     
0    1348   sedispatch                    1      81us      81us      
0    4254   kworker/0:0                   8      78us      302us     
5    0      swapper/5                     1      64us      64us      
0    2757   gsd-power                     2      37us      55us      
0    1543   gmain                         1      31us      31us      
0    2508   Xorg                          1      29us      29us      
0    1437   sssd_be                       2      28us      39us      
0    0      swapper/0                     1      8931ns    8931ns    
0    11     migration/0                   1      4355ns    4355ns    

Target task 4297
CPU  TID    COMM                          Count  Avg       Longest   
5    1387   irqbalance                    1      206us     206us     
5    0      swapper/5                     1      64us      64us      
5    35     migration/5                   1      24us      24us      
5    1447   sssd_nss                      2      20us      23us      
5    4492   schedsnoop                    4      11us      11us      
5    36     ksoftirqd/5                   1      9189ns    9189ns    
0    0      swapper/0                     1      8931ns    8931ns    
5    808    xfsaild/dm-0                  11     6524ns    20us      
5    3861   kworker/5:8                   5      4045ns    4301ns    

Target task 4295
CPU  TID    COMM                          Count  Avg       Longest   
2    1396   chronyd                       1      78us      78us      
5    0      swapper/5                     1      64us      64us      
2    948    kworker/2:3                   2      56us      56us      
0    0      swapper/0                     1      8931ns    8931ns    
```
