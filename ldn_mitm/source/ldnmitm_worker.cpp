/*
 * Copyright (c) 2018 Atmosphère-NX
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
 
#include <mutex>
#include <switch.h>
#include <stratosphere.hpp>
#include "ldnmitm_worker.hpp"
#include "debug.h"

static std::unique_ptr<MultiThreadedWaitableManager> g_worker_waiter;

void LdnMitMWorker::AddWaitable(IWaitable *waitable) {
    g_worker_waiter->add_waitable(waitable);
}

void LdnMitMWorker::Main(void *arg) {
    /* Make a new waitable manager. */
    g_worker_waiter = std::make_unique<MultiThreadedWaitableManager>(2, U64_MAX, 0x20000);
    
    /* Service processes. */
    g_worker_waiter->process();
}
