# journalhook

systemd-journald hook for logrus

[![wercker status](https://app.wercker.com/status/2d466972b06fc3fd47c18de8ffc6393d/m/master "wercker status")](https://app.wercker.com/project/bykey/2d466972b06fc3fd47c18de8ffc6393d)

## Use

```go
import "github.com/wercker/journalhook"

journalhook.Enable()
```

Note that this will discard all journal output. Generally when logging to the
journal, your application will be managed by systemd, which will automatically
capture command output and send it to the journal. This way we preempt that
potential log message duplication.

If you'd like not to do that, it's as easy as:

```go

import (
    "github.com/wercker/journalhook"
    "github.com/sirupsen/logrus"
)

logrus.AddHook(&journalhook.JournalHook{})
```
