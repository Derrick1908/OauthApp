using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data.SqlClient;
using System.Linq;
using System.Web;

namespace OauthApp.Repository
{
    public class ValidUser
    {
        public bool UserExists(int id)
        {
            bool exists = false;
            try
            {
                using (var connection = new SqlConnection(ConfigurationManager.ConnectionStrings["DefaultConnectionn"].ConnectionString))
                {
                    connection.Open();
                    string query = "select * from TokenInformation where userid = @useridd;";
                    using (SqlCommand myCommand = new SqlCommand(query, connection))
                    {
                        myCommand.Parameters.AddWithValue("@useridd", id);
                        using (SqlDataReader reader = myCommand.ExecuteReader())
                        {
                            if (reader.Read())
                            {
                                exists = true;
                                return exists;
                            }
                            else
                                return exists;
                        }
                    }
                }
            }
            catch (Exception)
            {
                return exists;
            }
        }                          //End of User Exists Function

        public bool UnauthorisedUser(int id, string token)
        {
            bool isunauthorised = true;
            try
            {
                using (var connection = new SqlConnection(ConfigurationManager.ConnectionStrings["DefaultConnectionn"].ConnectionString))
                {
                    connection.Open();
                    string query = "select userid, token from TokenInformation where userid = @useridd;";
                    using (SqlCommand myCommand = new SqlCommand(query, connection))
                    {
                        myCommand.Parameters.AddWithValue("@useridd", id);
                        using (SqlDataReader reader = myCommand.ExecuteReader())
                        {
                            if (reader.Read())
                            {
                                if (Int32.Parse(reader["userid"].ToString()) == id && reader["token"].ToString() == token)
                                {
                                    isunauthorised = false;
                                    return isunauthorised;
                                }
                                else
                                    return isunauthorised;

                            }
                            else
                                return isunauthorised;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                return isunauthorised;
            }
        }                    //End of Unauthorized User Function



        public bool DeleteUser(int id)
        {
            try
            {
                using (var connection = new SqlConnection(ConfigurationManager.ConnectionStrings["DefaultConnectionn"].ConnectionString))
                {
                        connection.Open();
                        string query = "delete from TokenInformation where userid = @useridd;";
                        using (SqlCommand myCommand = new SqlCommand(query, connection))
                        {
                            myCommand.Parameters.AddWithValue("@useridd", id);
                            int result = myCommand.ExecuteNonQuery();
                            if (result <= 0)
                                throw new Exception();
                        }
                }
                return true;
            }                            
            catch (Exception)
            {
                return false;
            }            

        }          //End of Delete User Function



    }
}