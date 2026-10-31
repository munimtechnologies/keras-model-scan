# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Builds the files for the pre-registered real-file check of
# r_serialized_scan (research/PREREG_RDS_REALFILE.md). Every object is only
# written; nothing here is read back, called or forced. The functions that
# mention system() are never called. Made with AI agents working in the name
# of MV2 of Munim, Inc.

args <- commandArgs(trailingOnly = TRUE)
out <- args[1]
dir.create(out, recursive = TRUE, showWarnings = FALSE)
p <- function(name) file.path(out, name)

status <- character()
step <- function(id, code) {
  res <- tryCatch({
    code
    "ok"
  }, error = function(e) paste("error:", conditionMessage(e)))
  status <<- c(status, paste(id, res, sep = "\t"))
}

df <- data.frame(x = 1:6, y = c(1.5, 2.1, 2.9, 4.2, 5.1, 5.8),
                 s = letters[1:6])
bin <- data.frame(x = 1:8, k = c(0, 1, 1, 2, 3, 3, 4, 5), n = rep(5, 8))

step("R1", saveRDS(df, p("plain.rds")))
step("R2", saveRDS(lm(y ~ x, data = df), p("lm.rds")))
step("R3", saveRDS(glm(cbind(k, n - k) ~ x, family = binomial(), data = bin),
                   p("glm.rds")))
step("R4", saveRDS(rpart::rpart(Kyphosis ~ Age + Number + Start,
                                data = rpart::kyphosis), p("rpart.rds")))
step("R5", saveRDS(function(cmd) system(cmd), p("fn_system.rds")))
step("R6", saveRDS(compiler::cmpfun(function(cmd) system(cmd)),
                   p("fn_system_bc.rds")))
step("R7", {
  e <- new.env()
  delayedAssign("x", Sys.time(), eval.env = globalenv(), assign.env = e)
  saveRDS(e, p("promise.rds"))
})
step("R8", {
  a <- new.env()
  makeActiveBinding("x", function() Sys.time(), a)
  saveRDS(a, p("active.rds"))
})
step("R9", saveRDS(list(f = rpart::rpart), p("pkgfun.rds")))
step("R10", saveRDS(function(cmd) system(cmd), p("fn_ascii.rds"),
                    ascii = TRUE, compress = FALSE))
step("R11", saveRDS(df, p("plain_xz.rds"), compress = "xz"))
step("R12", saveRDS(df, p("plain_bz2.rds"), compress = "bzip2"))
step("R13", {
  fit <- lm(y ~ x, data = df)
  save(df, fit, file = p("workspace.RData"))
})
step("R14", saveRDS(df, p("plain_v2.rds"), version = 2))
step("R15", saveRDS(1:10, p("altrep.rds")))

writeLines(status, p("build_status.tsv"))
writeLines(R.version.string, p("r_version.txt"))
