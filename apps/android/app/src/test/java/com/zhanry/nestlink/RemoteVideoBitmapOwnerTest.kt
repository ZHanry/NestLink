package com.zhanry.nestlink

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class RemoteVideoBitmapOwnerTest {
    @Test
    fun reservationsBoundTheNumberOfOutstandingDisplayBitmaps() {
        val owner = RemoteVideoBitmapOwner(maxOutstandingBitmaps = 2)

        val first = owner.reserve()
        val second = owner.reserve()
        assertNotNull(first)
        assertNotNull(second)
        assertEquals(2, owner.outstandingCount)
        assertNull(owner.reserve())

        first!!.close()
        assertEquals(1, owner.outstandingCount)
        val replacement = owner.reserve()
        assertNotNull(replacement)
        assertEquals(2, owner.outstandingCount)

        second!!.close()
        replacement!!.close()
        assertEquals(0, owner.outstandingCount)
    }
}
