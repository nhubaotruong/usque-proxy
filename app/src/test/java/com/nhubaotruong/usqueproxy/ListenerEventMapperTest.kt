package com.nhubaotruong.usqueproxy

import com.nhubaotruong.usqueproxy.vpn.ListenerEventMapper
import com.nhubaotruong.usqueproxy.vpn.VpnServiceEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ListenerEventMapperTest {
    @Test
    fun mapsGoStatesToEvents() {
        assertEquals(VpnServiceEvent.Connecting, ListenerEventMapper.mapState("connecting"))
        assertEquals(VpnServiceEvent.Started, ListenerEventMapper.mapState("connected"))
        assertEquals(VpnServiceEvent.Disconnecting, ListenerEventMapper.mapState("disconnected"))
        assertEquals(VpnServiceEvent.Stopped, ListenerEventMapper.mapState("stopped"))
        assertNull(ListenerEventMapper.mapState("unknown"))
    }

    @Test
    fun mapsErrors() {
        assertEquals(VpnServiceEvent.Error("boom"), ListenerEventMapper.mapError("boom"))
    }

    @Test
    fun dedupsRepeatedErrors() {
        assertEquals(VpnServiceEvent.Error("first"), ListenerEventMapper.mapError("first"))
        assertNull(ListenerEventMapper.mapError("first"))
        assertEquals(VpnServiceEvent.Error("second"), ListenerEventMapper.mapError("second"))
    }

    @Test
    fun resetsDedupOnReconnect() {
        assertEquals(VpnServiceEvent.Error("reconnect-err"), ListenerEventMapper.mapError("reconnect-err"))
        assertNull(ListenerEventMapper.mapError("reconnect-err"))
        ListenerEventMapper.mapState("connected")
        assertEquals(VpnServiceEvent.Error("reconnect-err"), ListenerEventMapper.mapError("reconnect-err"))
    }
}
