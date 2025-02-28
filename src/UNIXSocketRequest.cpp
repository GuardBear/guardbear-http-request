/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 11, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "UNIXSocketRequest.hpp"
#include "factoryRequestImplemetator.hpp"
#include "urlRequest.hpp"
#include <atomic>
#include <string>
#include <unordered_set>

using wrapperType = cURLWrapper;

void UNIXSocketRequest::download(
    std::variant<TRequestParameters<std::string>, TRequestParameters<nlohmann::json>> requestParameters,
    PostRequestParameters postRequestParameters = {},
    ConfigurationParameters configurationParameters = {})
{
    // Post request parameters
    const auto& onError {postRequestParameters.onError};
    const auto& onSuccess {postRequestParameters.onSuccess};
    const auto& outputFile {postRequestParameters.outputFile};
    // Configuration parameters
    const auto& timeout {configurationParameters.timeout};
    const auto& userAgent {configurationParameters.userAgent};
    const auto& handlerType {configurationParameters.handlerType};
    const auto& shouldRun {configurationParameters.shouldRun};

    try
    {
        std::visit(
            [&](auto&& arg)
            {
                GetRequest::builder(FactoryRequestWrapper<wrapperType>::create(handlerType, shouldRun))
                    .url(arg.url.url(), arg.secureCommunication)
                    .unixSocketPath(arg.url.unixSocketPath())
                    .timeout(timeout)
                    .userAgent(userAgent)
                    .outputFile(outputFile)
                    .execute();
            },
            requestParameters);
    }
    catch (const Curl::CurlException& ex)
    {
        if (onError)
        {
            onError(ex.what(), ex.responseCode());
        }
        else
        {
            throw;
        }
    }
    catch (const std::exception& ex)
    {
        if (onError)
        {
            onError(ex.what(), NOT_USED);
        }
        else
        {
            throw;
        }
    }
}

void UNIXSocketRequest::post(
    std::variant<TRequestParameters<std::string>, TRequestParameters<nlohmann::json>> requestParameters,
    PostRequestParameters postRequestParameters = {},
    ConfigurationParameters configurationParameters = {})
{
    // Post request parameters
    const auto& onError {postRequestParameters.onError};
    const auto& onSuccess {postRequestParameters.onSuccess};
    const auto& outputFile {postRequestParameters.outputFile};
    // Configuration parameters
    const auto& timeout {configurationParameters.timeout};
    const auto& userAgent {configurationParameters.userAgent};
    const auto& handlerType {configurationParameters.handlerType};
    const auto& shouldRun {configurationParameters.shouldRun};

    try
    {
        std::visit(
            [&](auto&& arg)
            {
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, TRequestParameters<std::string>>)
                {
                    auto req {PostRequest::builder(FactoryRequestWrapper<wrapperType>::create(handlerType, shouldRun))};
                    req.url(arg.url.url(), arg.secureCommunication)
                        .unixSocketPath(arg.url.unixSocketPath())
                        .timeout(timeout)
                        .userAgent(userAgent)
                        .postData(arg.data)
                        .outputFile(outputFile)
                        .execute();

                    onSuccess(req.response());
                }
                else if constexpr (std::is_same_v<T, TRequestParameters<nlohmann::json>>)
                {
                    const auto data = arg.data.dump();
                    auto req {PostRequest::builder(FactoryRequestWrapper<wrapperType>::create(handlerType, shouldRun))};
                    req.url(arg.url.url(), arg.secureCommunication)
                        .unixSocketPath(arg.url.unixSocketPath())
                        .timeout(timeout)
                        .userAgent(userAgent)
                        .postData(data)
                        .outputFile(outputFile)
                        .execute();

                    onSuccess(req.response());
                }
                else
                {
                    throw std::runtime_error("Invalid type");
                }
            },
            requestParameters);
    }
    catch (const Curl::CurlException& ex)
    {
        if (onError)
        {
            onError(ex.what(), ex.responseCode());
        }
        else
        {
            throw;
        }
    }
    catch (const std::exception& ex)
    {
        if (onError)
        {
            onError(ex.what(), NOT_USED);
        }
        else
        {
            throw;
        }
    }
}

void UNIXSocketRequest::get(
    std::variant<TRequestParameters<std::string>, TRequestParameters<nlohmann::json>> requestParameters,
    PostRequestParameters postRequestParameters = {},
    ConfigurationParameters configurationParameters = {})
{
    // Post request parameters
    const auto& onError {postRequestParameters.onError};
    const auto& onSuccess {postRequestParameters.onSuccess};
    const auto& outputFile {postRequestParameters.outputFile};
    // Configuration parameters
    const auto& timeout {configurationParameters.timeout};
    const auto& userAgent {configurationParameters.userAgent};
    const auto& handlerType {configurationParameters.handlerType};
    const auto& shouldRun {configurationParameters.shouldRun};

    try
    {
        std::visit(
            [&](auto&& arg)
            {
                auto req {GetRequest::builder(FactoryRequestWrapper<wrapperType>::create(handlerType, shouldRun))};
                req.url(arg.url.url(), arg.secureCommunication)
                    .unixSocketPath(arg.url.unixSocketPath())
                    .timeout(timeout)
                    .userAgent(userAgent)
                    .outputFile(outputFile)
                    .execute();

                onSuccess(req.response());
            },
            requestParameters);
    }
    catch (const Curl::CurlException& ex)
    {
        if (onError)
        {
            onError(ex.what(), ex.responseCode());
        }
        else
        {
            throw;
        }
    }
    catch (const std::exception& ex)
    {
        if (onError)
        {
            onError(ex.what(), NOT_USED);
        }
        else
        {
            throw;
        }
    }
}

void UNIXSocketRequest::put(
    std::variant<TRequestParameters<std::string>, TRequestParameters<nlohmann::json>> requestParameters,
    PostRequestParameters postRequestParameters = {},
    ConfigurationParameters configurationParameters = {})
{
    // Post request parameters
    const auto& onError {postRequestParameters.onError};
    const auto& onSuccess {postRequestParameters.onSuccess};
    const auto& outputFile {postRequestParameters.outputFile};
    // Configuration parameters
    const auto& timeout {configurationParameters.timeout};
    const auto& userAgent {configurationParameters.userAgent};
    const auto& handlerType {configurationParameters.handlerType};
    const auto& shouldRun {configurationParameters.shouldRun};

    try
    {
        std::visit(
            [&](auto&& arg)
            {
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, TRequestParameters<std::string>>)
                {
                    auto req {PutRequest::builder(FactoryRequestWrapper<wrapperType>::create(handlerType, shouldRun))};
                    req.url(arg.url.url(), arg.secureCommunication)
                        .unixSocketPath(arg.url.unixSocketPath())
                        .timeout(timeout)
                        .userAgent(userAgent)
                        .postData(arg.data)
                        .outputFile(outputFile)
                        .execute();

                    onSuccess(req.response());
                }
                else if constexpr (std::is_same_v<T, TRequestParameters<nlohmann::json>>)
                {
                    const auto data = arg.data.dump();
                    auto req {PutRequest::builder(FactoryRequestWrapper<wrapperType>::create(handlerType, shouldRun))};
                    req.url(arg.url.url(), arg.secureCommunication)
                        .postData(data)
                        .appendHeaders(arg.httpHeaders)
                        .timeout(timeout)
                        .userAgent(userAgent)
                        .outputFile(outputFile)
                        .execute();

                    onSuccess(req.response());
                }
                else
                {
                    throw std::runtime_error("Invalid type");
                }
            },
            requestParameters);
    }
    catch (const Curl::CurlException& ex)
    {
        if (onError)
        {
            onError(ex.what(), ex.responseCode());
        }
        else
        {
            throw;
        }
    }
    catch (const std::exception& ex)
    {
        if (onError)
        {
            onError(ex.what(), NOT_USED);
        }
        else
        {
            throw;
        }
    }
}

void UNIXSocketRequest::patch(
    std::variant<TRequestParameters<std::string>, TRequestParameters<nlohmann::json>> requestParameters,
    PostRequestParameters postRequestParameters = {},
    ConfigurationParameters configurationParameters = {})
{
    // Post request parameters
    const auto& onError {postRequestParameters.onError};
    const auto& onSuccess {postRequestParameters.onSuccess};
    const auto& outputFile {postRequestParameters.outputFile};
    // Configuration parameters
    const auto& timeout {configurationParameters.timeout};
    const auto& userAgent {configurationParameters.userAgent};
    const auto& handlerType {configurationParameters.handlerType};
    const auto& shouldRun {configurationParameters.shouldRun};

    try
    {
        std::visit(
            [&](auto&& arg)
            {
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, TRequestParameters<std::string>>)
                {
                    auto req {
                        PatchRequest::builder(FactoryRequestWrapper<wrapperType>::create(handlerType, shouldRun))};
                    req.url(arg.url.url(), arg.secureCommunication)
                        .unixSocketPath(arg.url.unixSocketPath())
                        .timeout(timeout)
                        .userAgent(userAgent)
                        .postData(arg.data)
                        .outputFile(outputFile)
                        .execute();

                    onSuccess(req.response());
                }
                else if constexpr (std::is_same_v<T, TRequestParameters<nlohmann::json>>)
                {
                    const auto data = arg.data.dump();
                    auto req {
                        PatchRequest::builder(FactoryRequestWrapper<wrapperType>::create(handlerType, shouldRun))};
                    req.url(arg.url.url(), arg.secureCommunication)
                        .unixSocketPath(arg.url.unixSocketPath())
                        .timeout(timeout)
                        .userAgent(userAgent)
                        .postData(data)
                        .outputFile(outputFile)
                        .execute();

                    onSuccess(req.response());
                }
                else
                {
                    throw std::runtime_error("Invalid type");
                }
            },
            requestParameters);
    }
    catch (const Curl::CurlException& ex)
    {
        if (onError)
        {
            onError(ex.what(), ex.responseCode());
        }
        else
        {
            throw;
        }
    }
    catch (const std::exception& ex)
    {
        if (onError)
        {
            onError(ex.what(), NOT_USED);
        }
        else
        {
            throw;
        }
    }
}

void UNIXSocketRequest::delete_(
    std::variant<TRequestParameters<std::string>, TRequestParameters<nlohmann::json>> requestParameters,
    PostRequestParameters postRequestParameters = {},
    ConfigurationParameters configurationParameters = {})
{
    // Post request parameters
    const auto& onError {postRequestParameters.onError};
    const auto& onSuccess {postRequestParameters.onSuccess};
    const auto& outputFile {postRequestParameters.outputFile};
    // Configuration parameters
    const auto& timeout {configurationParameters.timeout};
    const auto& userAgent {configurationParameters.userAgent};
    const auto& handlerType {configurationParameters.handlerType};
    const auto& shouldRun {configurationParameters.shouldRun};

    try
    {
        std::visit(
            [&](auto&& arg)
            {
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, TRequestParameters<std::string>>)
                {
                    auto req {
                        DeleteRequest::builder(FactoryRequestWrapper<wrapperType>::create(handlerType, shouldRun))};
                    req.url(arg.url.url(), arg.secureCommunication)
                        .unixSocketPath(arg.url.unixSocketPath())
                        .timeout(timeout)
                        .userAgent(userAgent)
                        .outputFile(outputFile)
                        .execute();

                    onSuccess(req.response());
                }
                else if constexpr (std::is_same_v<T, TRequestParameters<nlohmann::json>>)
                {
                    const auto data = arg.data.dump();
                    auto req {
                        DeleteRequest::builder(FactoryRequestWrapper<wrapperType>::create(handlerType, shouldRun))};
                    req.url(arg.url.url(), arg.secureCommunication)
                        .unixSocketPath(arg.url.unixSocketPath())
                        .timeout(timeout)
                        .userAgent(userAgent)
                        .outputFile(outputFile)
                        .execute();

                    onSuccess(req.response());
                }
                else
                {
                    throw std::runtime_error("Invalid type");
                }
            },
            requestParameters);
    }
    catch (const Curl::CurlException& ex)
    {
        if (onError)
        {
            onError(ex.what(), ex.responseCode());
        }
        else
        {
            throw;
        }
    }
    catch (const std::exception& ex)
    {
        if (onError)
        {
            onError(ex.what(), NOT_USED);
        }
        else
        {
            throw;
        }
    }
}
