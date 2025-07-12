package com.supplementtracker.data.network

import com.supplementtracker.data.model.*
import retrofit2.Response
import retrofit2.http.*

interface ApiService {

    @POST("api/login")
    suspend fun login(@Body request: LoginRequest): Response<LoginResponse>

    @POST("api/verify_2fa")
    suspend fun verify2FA(@Body request: TwoFARequest): Response<LoginResponse>

    @GET("api/protocols")
    suspend fun getProtocols(): Response<List<Protocol>>

    @GET("api/compounds")
    suspend fun getAvailableCompounds(): Response<CompoundsResponse>

    @POST("api/compounds")
    suspend fun addCustomCompound(@Body request: AddCompoundRequest): Response<BaseResponse>

    @POST("api/protocols")
    suspend fun createProtocol(@Body request: CreateProtocolRequest): Response<Protocol>

    @POST("api/protocols/{protocolId}/log")
    suspend fun saveProtocolLog(
        @Path("protocolId") protocolId: String,
        @Body request: ProtocolLogRequest
    ): Response<Void>

    @GET("api/protocols/{protocolId}/analytics")
    suspend fun getProtocolAnalytics(@Path("protocolId") protocolId: String): Response<Analytics>

    @GET("api/protocols/{protocolId}/calendar")
    suspend fun getProtocolCalendar(@Path("protocolId") protocolId: String): Response<List<CalendarEvent>>

    @GET("api/notifications")
    suspend fun getNotifications(): Response<List<Notification>>

    @POST("api/notifications/{notificationId}/read")
    suspend fun markNotificationAsRead(@Path("notificationId") notificationId: String): Response<Void>

    @GET("api/user/profile")
    suspend fun getUserProfile(): Response<User>
}