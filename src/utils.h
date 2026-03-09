#pragma once

#include <stddef.h>
#include <stdint.h>
#include "mining.h"
#include "stratum.h"
#include "mining_core.h"

/* Arduino/ESP32-dependent functions (not portable to native tests) */
miner_data calculateMiningData(mining_subscribe& mWorker, mining_job mJob);
