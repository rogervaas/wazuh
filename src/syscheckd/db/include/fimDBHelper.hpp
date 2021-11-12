/*
 * Wazuh Syscheckd
 * Copyright (C) 2015-2021, Wazuh Inc.
 * September 23, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FIMDBHELPER_HPP
#define _FIMDBHELPER_HPP
#include "fimDB.hpp"
#include "dbItem.hpp"

namespace FIMDBHelper
{

    int initDB(const std::string&, int, int, void(*sync_callback)(const char* log, const char* tag), void(*loggFunction)(modules_log_level_t level));

    /**
    * @brief Insert a new row from a table.
    *
    * @param tableName a string with the table name
    * @param item a RegistryKey, RegistryValue or File with their parameters
    *
    * @return 0 on success, another value otherwise.
    */
    int insertItem(const std::string &, const nlohmann::json &);

    /**
    * @brief Get count of all entries in a table
    *
    * @param tableName a string with the table name
    *
    * @return amount of entries on success, 0 otherwise.
    */
    int getCount(const std::string &);

    /**
    * @brief Get a item from a query
    *
    * @param item a item object where will be saved the query information
    * @param query a json with a query to the database
    *
    * @return a file, registryKey or registryValue, nullptr otherwise.
    */
    int getDBItem(DBItem &, const nlohmann::json &);

    /**
    * @brief Delete a row from a table
    *
    * @param tableName a string with the table name
    * @param query a json with a filter to delete an element to the database
    *
    * @return 0 on success, another value otherwise.
    */
    int removeFromDB(const std::string &, const nlohmann::json &);

    /**
    * @brief Update a row from a table.
    *
    * @param tableName a string with the table name
    * @param item a RegistryKey, RegistryValue or File with their parameters
    *
    * @return 0 on success, another value otherwise.
    */
    int updateItem(const std::string &, const nlohmann::json &);

    // Template function must be defined in fimHelper.hpp
    template<typename T>
    int FIMDBHelper::removeFromDB(const std::string& tableName, const nlohmann::json& filter)
    {
        auto deleteJson = R"({
                                "table": "",
                                "query": {
                                    "data":[
                                    {
                                    }],
                                    "where_filter_opt":""
                                }
        })"_json;
        deleteJson["table"] = tableName;
        deleteJson["query"]["data"] = {filter};

        return T::getInstance().removeItem(deleteJson);
    }

    template<typename T>
    int FIMDBHelper::getCount(const std::string & tableName)
    {
        auto countQuery = R"({
                                "table":"",
                                "query":{"column_list":["count(*) AS count"],
                                "row_filter":"",
                                "distinct_opt":false,
                                "order_by_opt":"",
                                "count_opt":100}
        })"_json;
        countQuery["table"] = tableName;
        auto count = 0;
        auto callback {
            [&count](ReturnTypeCallback type, const nlohmann::json & jsonResult)
            {
            }
        };
        T::getInstance().executeQuery(countQuery, callback);

        return count;
    }

    template<typename T>
    int FIMDBHelper::insertItem(const std::string & tableName, const nlohmann::json & item)
    {
        auto insertStatement = R"(
                                {
                                    "table": "",
                                    "data":[
                                        {
                                        }
                                    ]
                                }
        )"_json;
        insertStatement["table"] = tableName;
        insertStatement["data"] = {item};

        return T::getInstance().insertItem(insertStatement);
    }

    template<typename T>
    int FIMDBHelper::updateItem(const std::string & tableName, const nlohmann::json & item)
    {
        auto updateStatement = R"(
                                {
                                    "table": "",
                                    "data":[
                                        {
                                        }
                                    ]
                                }
        )"_json;
        updateStatement["table"] = tableName;
        updateStatement["data"] = {item};
        auto callback {
            [](ReturnTypeCallback type, const nlohmann::json & jsonResult)
            {
            }
        };

        return T::getInstance().updateItem(updateStatement, callback);
    }

    template<typename T>
    int FIMDBHelper::getDBItem(DBItem & item, const nlohmann::json & query)
    {
        auto callback {
            [&item](ReturnTypeCallback type, const nlohmann::json & jsonResult)
            {
                //TODO: Parse query and generate a DBItem
            }
        };

        return T::getInstance().executeQuery(query, callback);
    }

    template<typename T>
    int FIMDBHelper::initDB(const std::string& path, unsigned int sync_interval, unsigned int file_limit,
                            fim_sync_callback_t sync_callback,
                            void(*loggFunction)(modules_log_level_t level))
    {
        auto handler_DBSync = std::make_shared<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, path, T::CreateStatement());
        auto handler_RSync = std::make_shared<RemoteSync>();

        T::getInstance().init(sync_interval, file_limit, sync_callback, loggFunction, handler_DBSync, handler_RSync);
    }
}

#endif //_FIMDBHELPER_H
